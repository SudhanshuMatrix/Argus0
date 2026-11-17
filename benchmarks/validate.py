"""Exercise Argus recovery, flow capacity and separate profiling in an isolated veth pair."""
import argparse
import contextlib
import concurrent.futures
import json
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time

from run import (
    HTTP_LOAD, IFACE, METRICS, SERVER, agent_config, curl, dump, listen_ready, nscmd,
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
        wait_for(child, lambda: bool(curl(namespace, "/readyz")), "Argus")
        dump(output / f"{name}.attached.json", query(args.probe, namespace, 1))
        yield child, log
    if name != "interface-loss":
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


def api_samples(namespace, path, stop):
    samples = []
    while not stop.is_set():
        fields = run(*nscmd(namespace, "curl", "-fsS", "--max-time", "3", "-o", "/dev/null",
                           "-w", "%{time_total} %{size_download}", METRICS + path)).split()
        samples.append({"seconds": float(fields[0]), "bytes": int(fields[1])})
        stop.wait(0.25)
    return samples


def last_collection(namespace):
    return json.loads(curl(namespace, "/api/stats"))["stats"]["collected_at"]


def await_collection(namespace, previous):
    until = time.monotonic() + 10
    while time.monotonic() < until:
        at = last_collection(namespace)
        if at != previous:
            return at
        time.sleep(0.05)
    raise RuntimeError("collection did not publish")


def scale(args, left, right, output):
    observations = []
    capacity = args.map_capacity
    batch = capacity * 9 // 10
    with contextlib.ExitStack() as stack:
        tally = output / "receiver.txt"
        receiver = stack.enter_context(process(nscmd(
            right, sys.executable, FLOW_LOAD, "receive", "--port", DESTINATION_PORT,
            "--outfile", tally
        ), output / "receiver.log"))
        wait_for(receiver, tally.is_file, "UDP receiver")
        child, _ = stack.enter_context(agent(args, left, output, "scale"))
        paths = ["/api/flows", "/api/stats", "/metrics"]
        stop = threading.Event()
        sent = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(paths)) as clients:
            futures = {path: clients.submit(api_samples, left, path, stop) for path in paths}
            try:
                at = await_collection(left, last_collection(left))
                for count in (batch,) * 12 + (capacity + 100,):
                    result = new_flows(left, SRC_PORT + sent, count, DESTINATION_PORT)
                    sent += count
                    at = await_collection(left, at)
                    expected = min(count, capacity)
                    failures = count - expected
                    text = curl(left, "/metrics")
                    page = json.loads(curl(left, "/api/flows?limit=100"))
                    sample = {
                        "sent_in_window": result,
                        "sent_total": sent,
                        "received_total": int(tally.read_text()),
                        "entries": metric(text, "network_flow_map_entries"),
                        "eligible_udp_egress_packets": metric(
                            text, "network_observed_packets_total", protocol="UDP", direction="egress"
                        ),
                        "detail_admission_failures": metric(text, "network_flow_update_failures_total"),
                        "observation_accounting_failures": metric(
                            text, "network_observation_accounting_failures_total"
                        ),
                        "page_rows": len(page["flows"]),
                        "generated_at": page["generated_at"],
                        "process": proc_sample(child),
                    }
                    observations.append(sample)
                    dump(output / "churn.json", observations)
                    if (sample["entries"] != expected or sample["eligible_udp_egress_packets"] != sent
                            or sample["detail_admission_failures"] != failures
                            or sample["observation_accounting_failures"]
                            or sample["page_rows"] > 100 or any(row.get("pid") for row in page["flows"])):
                        raise RuntimeError(f"unexpected flow accounting in window: {sample}")
                await_collection(left, at)
                idle = curl(left, "/metrics")
                (output / "idle.metrics").write_text(idle)
                if metric(idle, "network_flow_map_entries") or metric(idle, "network_active_connections"):
                    raise RuntimeError("idle flow details outlived their window")
                if int(tally.read_text()) > sent:
                    raise RuntimeError("UDP receiver counted unexpected packets")
                dump(output / "endpoint-loss.json", {"sent": sent, "received": int(tally.read_text())})
            finally:
                stop.set()
        dump(output / "api-samples.json", {path: future.result() for path, future in futures.items()})


def interface_disappearance(args, left, output):
    with agent(args, left, output, "interface-loss") as (child, _):
        run("ip", "-n", left, "link", "del", IFACE)
        wait_for(child, lambda: run(*nscmd(left, "curl", "-sS", "-o", "/dev/null",
                                          "-w", "%{http_code}", METRICS + "/readyz")) == "503",
                 "readiness after interface disappearance")
        if curl(left, "/healthz") != "ok":
            raise RuntimeError("liveness failed after interface disappearance")
        (output / "interface-loss.txt").write_text("readiness: 503\nliveness: 200\n")


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
    if not 100 <= args.map_capacity <= 3000:
        raise ValueError("--map-capacity must be between 100 and 3000 for the isolated churn fixture")
    agent_config(output / "agent.yaml", "2s", level="debug", capacity=args.map_capacity)
    with topology(output) as (left, right):
        scale(args, left, right, output)
        bind_failure(args, left, output)
        with process(nscmd(right, "iperf3", "-s", "-B", SERVER, "-p", 15201),
                     output / "iperf-server.log") as server:
            wait_for(server, lambda: listen_ready(right, 15201), "iperf3 server")
            profile(args, left, output)
            soak(args, left, output)
        interface_disappearance(args, left, output)
    dump(output / "status.json", {"status": "ok"})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--argus", type=lambda s: Path(s).resolve(), required=True)
    parser.add_argument("--probe", type=lambda s: Path(s).resolve(), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--map-capacity", type=positive, default=1000)
    parser.add_argument("--soak-seconds", type=positive, default=3600)
    parser.add_argument("--profile-seconds", type=positive, default=10)
    parser.add_argument("--sample-interval", type=positive, default=10)
    signal.signal(signal.SIGTERM, lambda *_: signal.raise_signal(signal.SIGINT))
    main(parser.parse_args())
