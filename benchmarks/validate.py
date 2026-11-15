"""Exercise Argus recovery, flow capacity and separate profiling in an isolated veth pair."""
import argparse
import contextlib
import json
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

from run import (
    HTTP_LOAD, IFACE, SERVER, agent_config, curl, dump, listen_ready, nscmd,
    positive, proc_sample, process, run, topology, validate, wait_for,
)

FLOW_LOAD = Path(__file__).resolve().with_name("flow_load.py")
RUNTIME_SETTING = Path("/proc/sys/kernel/bpf_stats_enabled")
DESTINATION_PORT = 15505
SRC_PORT = 20000


def metric(text, name, **labels):
    return sum(int(float(value)) for label_set, value in re.findall(
        rf"^{name}\{{([^}}]*)\}} ([^\s]+)$", text, re.M
    ) if all(f'{key}="{item}"' in label_set.split(",") for key, item in labels.items()))


def query(probe, namespace, count):
    data = json.loads(run(*nscmd(namespace, probe, "--interface", IFACE)))
    if any(len(data[direction]) != count for direction in ("ingress", "egress")):
        raise RuntimeError(f"expected {count} links per hook: {data}")
    return data


@contextlib.contextmanager
def agent(args, namespace, output, name):
    log = output / f"{name}.agent.log"
    config = output / "agent.yaml"
    dump(output / f"{name}.detached-before.json", query(args.probe, namespace, 0))
    with process(nscmd(namespace, args.argus, "-config", config), log, require_success=True, isolated_agent=True) as child:
        wait_for(child, lambda: curl(namespace, "/healthz") == "ok", "Argus")
        dump(output / f"{name}.attached.json", query(args.probe, namespace, 1))
        yield child, log
    dump(output / f"{name}.detached-after.json", query(args.probe, namespace, 0))


def await_metrics(namespace, test, timeout=60):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        text = curl(namespace, "/metrics")
        if test(text):
            return text
        time.sleep(0.5)
    raise RuntimeError("expected metrics did not arrive before timeout")


def new_flows(left, start, count, destination):
    return json.loads(run(*nscmd(
        left, sys.executable, FLOW_LOAD, "send", "--port", destination,
        "--start", start, "--count", count
    ), timeout=120))


def scale(args, left, right, output):
    observations = []
    with contextlib.ExitStack() as stack:
        receivers = []
        for index in range(4):
            tally = output / f"receiver-{index}.txt"
            child = stack.enter_context(process(nscmd(
                right, sys.executable, FLOW_LOAD, "receive", "--port", DESTINATION_PORT + index,
                "--outfile", tally
            ), output / f"receiver-{index}.log"))
            wait_for(child, tally.is_file, "UDP receiver")
            receivers.append(tally)
        child, log = stack.enter_context(agent(args, left, output, "scale"))
        previous = 0
        for target in (100, 1000, 10000, 100100):
            sent = []
            while previous < target:
                remaining = 30000 - previous % 30000
                count = min(remaining, target - previous)
                sent.append(new_flows(left, SRC_PORT + previous % 30000, count,
                                      DESTINATION_PORT + previous // 30000))
                previous += count
            expected = min(100000, target)
            failures = target - expected
            text = await_metrics(left, lambda text: (
                metric(text, "network_flow_map_entries") == expected
                and metric(text, "network_packets_total", protocol="UDP", direction="egress") == expected
                and metric(text, "network_flow_update_failures_total") == failures
            ))
            time.sleep(0.4)
            collections = [json.loads(line) for line in log.read_text().splitlines()]
            durations = [sample["duration_ns"] for sample in collections
                         if sample.get("count") == expected and "duration_ns" in sample]
            observations.append({
                "sent_flows": target,
                "sender_runs": sent,
                "receiver_packets": sum(int(tally.read_text()) for tally in receivers),
                "map_entries": expected,
                "argus_udp_egress_packets": metric(text, "network_packets_total", protocol="UDP", direction="egress"),
                "flow_update_failures": failures,
                "collection_duration_ns": durations,
                "process": proc_sample(child),
            })
            if target == 100:
                snapshot = json.loads(curl(left, "/api/flows"))
                if snapshot["count"] != expected or any(flow["pid"] for flow in snapshot["flows"]):
                    raise RuntimeError("unexpected flow count or process attribution")
                dump(output / "known-process-flows.json", {
                    "sender_pid": sent[0]["sender_pid"],
                    "reported_pids": sorted({flow["pid"] for flow in snapshot["flows"]}),
                    "count": snapshot["count"],
                })
            dump(output / "flow-scale.json", observations)
        text = await_metrics(left, lambda text: (
            metric(text, "network_active_connections") == 0
            and metric(text, "network_flow_map_entries") == 100000
        ))
        (output / "after-traffic-stopped.metrics").write_text(
            "\n".join(line for line in text.splitlines() if line.startswith("network_")) + "\n"
        )


def bind_failure(args, left, output):
    with process(nscmd(left, sys.executable, HTTP_LOAD, "server", "127.0.0.1", 19090),
                 output / "conflicting-server.log") as server:
        wait_for(server, lambda: listen_ready(left, 19090), "conflicting HTTP server")
        attempt = subprocess.run(nscmd(left, args.argus, "-config", output / "agent.yaml"),
                                 capture_output=True, text=True, timeout=20)
        if attempt.returncode == 0 or "address already in use" not in attempt.stderr:
            raise RuntimeError(f"expected HTTP bind failure: {attempt.stderr}")
        (output / "bind-failure.txt").write_text(attempt.stdout + attempt.stderr)
        dump(output / "bind-failure-detached.json", query(args.probe, left, 0))


def udp(left, seconds):
    return nscmd(left, "iperf3", "-c", SERVER, "-p", 15201, "-J", "-u",
                 "-b", "5M", "-l", 1200, "-t", seconds)


def verify_udp(data, seconds):
    received = data["end"]["sum_received"]
    if received["seconds"] < 0.9 * seconds or not received["packets"]:
        raise RuntimeError("incomplete UDP receiver measurement")


def soak(args, left, output):
    with agent(args, left, output, "soak") as (child, _):
        text = curl(left, "/metrics")
        if metric(text, "network_flow_map_entries") != 0:
            raise RuntimeError("restart did not begin with an empty flow map")
        before = time.monotonic()
        samples = []
        log = output / "soak.traffic.json"
        with process(udp(left, args.soak_seconds), log, require_success=True) as traffic:
            while traffic.poll() is None:
                last = curl(left, "/metrics")
                samples.append(proc_sample(child) | {
                    "entries": metric(last, "network_flow_map_entries"),
                    "failures": metric(last, "network_flow_update_failures_total"),
                })
                if time.monotonic() - before > args.soak_seconds + 20:
                    raise RuntimeError("soak traffic ran beyond its time budget")
                time.sleep(args.sample_interval)
        verify_udp(json.loads(log.read_text()), args.soak_seconds)
        final = await_metrics(left, lambda text: metric(text, "network_active_connections") == 0)
        failures = metric(final, "network_flow_update_failures_total")
        dump(output / "soak.json", {
            "configured_seconds": args.soak_seconds, "wall_seconds": time.monotonic() - before,
            "samples": samples,
            "final_flow_update_failures": failures,
        })
        if failures:
            raise RuntimeError("unexpected accounting failures during soak")


def profile(args, left, output):
    initial_setting = RUNTIME_SETTING.read_text().strip()
    try:
        logfile = output / "runtime-stats.log"
        with process((args.probe, "--hold-stats"), logfile, require_success=True) as stats:
            wait_for(stats, lambda: "enabled" in logfile.read_text(), "BPF runtime statistics")
            with agent(args, left, output, "profile"):
                before = query(args.probe, left, 1)
                workload = run(*udp(left, args.profile_seconds), timeout=args.profile_seconds + 25)
                (output / "profile.traffic.json").write_text(workload)
                verify_udp(json.loads(workload), args.profile_seconds)
                after = query(args.probe, left, 1)
                observed = {}
                for direction in ("ingress", "egress"):
                    first, last = before[direction][0], after[direction][0]
                    if first["id"] != last["id"]:
                        raise RuntimeError("BPF program changed during profiling")
                    count = last["run_count"] - first["run_count"]
                    runtime = last["runtime_ns"] - first["runtime_ns"]
                    if count <= 0 or runtime <= 0:
                        raise RuntimeError(f"missing {direction} runtime counters")
                    observed[direction] = {
                        "invocations": count, "runtime_ns": runtime,
                        "ns_per_invocation": runtime / count,
                    }
                dump(output / "profile.json", {"before": before, "after": after, "deltas": observed})
    finally:
        restored = RUNTIME_SETTING.read_text().strip()
        dump(output / "runtime-setting.json", {"before": initial_setting, "after": restored})
        if restored != initial_setting:
            raise RuntimeError("unexpected change to BPF runtime statistics sysctl")


def main(args):
    versions = validate(args)
    if not args.probe.is_file():
        raise ValueError("--probe must point to the built bpfprobe")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    dump(output / "configuration.json", vars(args) | {
        "argus": str(args.argus), "output": str(output), "probe": str(args.probe),
        "versions": versions,
    })
    agent_config(output / "agent.yaml", "2s", level="debug")
    with topology(output) as (left, right):
        scale(args, left, right, output)
        bind_failure(args, left, output)
        with process(nscmd(right, "iperf3", "-s", "-B", SERVER, "-p", 15201),
                     output / "iperf-server.log") as server:
            wait_for(server, lambda: listen_ready(right, 15201), "iperf3 server")
            profile(args, left, output)
            soak(args, left, output)
    dump(output / "status.json", {"status": "ok"})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--argus", type=lambda s: Path(s).resolve(), required=True)
    parser.add_argument("--probe", type=lambda s: Path(s).resolve(), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--soak-seconds", type=positive, default=3600)
    parser.add_argument("--profile-seconds", type=positive, default=10)
    parser.add_argument("--sample-interval", type=positive, default=10)
    signal.signal(signal.SIGTERM, lambda *_: signal.raise_signal(signal.SIGINT))
    main(parser.parse_args())
