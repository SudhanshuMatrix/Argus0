"""Run paired isolated veth benchmarks. Requires Linux namespace and BPF privileges."""
import argparse
import contextlib
import hashlib
import itertools
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid

CLIENT = "198.18.0.1"
SERVER = "198.18.0.2"
METRICS = "http://127.0.0.1:19090"
IFACE = "argus0"
IPERF_VERSION = "3.19.1"
HTTP_LOAD = Path(__file__).resolve().with_name("http_load.py")


def dump(path, data):
    path.write_text(json.dumps(data, indent=2, allow_nan=False) + "\n")


def run(*args, timeout=20):
    return subprocess.run(args, text=True, check=True, capture_output=True, timeout=timeout).stdout


def nscmd(namespace, *args):
    return ("ip", "netns", "exec", namespace, *map(str, args))


@contextlib.contextmanager
def process(args, logfile, require_success=False, isolated_agent=False):
    with logfile.open("w") as log:
        env = None
        cwd = None
        if isolated_agent:
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith("ARGUS_") and key not in ("INTERFACE", "PORT")}
            cwd = logfile.parent
        child = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT,
                                 start_new_session=True, env=env, cwd=cwd)
        try:
            yield child
        finally:
            forced = False
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    forced = True
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=5)
            if require_success and (forced or child.returncode != 0):
                raise RuntimeError(f"{args[0]} failed to exit cleanly ({child.returncode}); see {logfile}")


@contextlib.contextmanager
def topology(output):
    prefix = "av" + uuid.uuid4().hex[:8]
    left, right = prefix + "a", prefix + "b"
    created = []
    try:
        for namespace in (left, right):
            run("ip", "netns", "add", namespace)
            created.append(namespace)
        run("ip", "link", "add", IFACE, "netns", left, "type", "veth",
            "peer", "name", IFACE, "netns", right)
        for namespace, address in ((left, CLIENT), (right, SERVER)):
            run("ip", "-n", namespace, "addr", "add", address + "/30", "dev", IFACE)
            run("ip", "-n", namespace, "link", "set", IFACE, "up")
            run("ip", "-n", namespace, "link", "set", "lo", "up")
            for command, filename in (
                (("ip", "-d", "link", "show", IFACE), "link"),
                (("ethtool", "-k", IFACE), "offloads"),
                (("ip", "route", "show"), "routes"),
            ):
                (output / f"{namespace[-1]}-{filename}.txt").write_text(run(*nscmd(namespace, *command)))
        yield left, right
    finally:
        errors = []
        for namespace in reversed(created):
            try:
                run("ip", "netns", "del", namespace)
            except (subprocess.SubprocessError, OSError) as err:
                errors.append(f"{namespace}: {err}")
        residual = {line.split()[0] for line in run("ip", "netns", "list").splitlines() if line}
        errors.extend(f"{namespace}: still present" for namespace in created if namespace in residual)
        dump(output / "cleanup.json", {"created_namespaces": created, "errors": errors})
        if errors:
            raise RuntimeError("; ".join(errors))


def wait_for(child, check, name):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and child.poll() is None:
        try:
            if check():
                return
        except subprocess.CalledProcessError:
            pass
        time.sleep(0.1)
    raise RuntimeError(f"{name} readiness failed; process exit={child.poll()}")


def listen_ready(namespace, port):
    return run(*nscmd(namespace, "ss", "-H", "-ltn", f"sport = :{port}")).strip()


def proc_sample(child):
    proc = Path(f"/proc/{child.pid}")
    stat = (proc / "stat").read_text().rsplit(")", 1)[1].split()
    status = (proc / "status").read_text()
    return {
        "monotonic_seconds": time.monotonic(),
        "cpu_ticks": int(stat[11]) + int(stat[12]),
        "rss_kib": int(re.search(r"^VmRSS:\s+(\d+)", status, re.M)[1]),
    }


def cpu_sample():
    fields = Path("/proc/stat").read_text().splitlines()[0].split()[1:]
    return [int(field) for field in fields]


def curl(namespace, path):
    return run(*nscmd(namespace, "curl", "-fsS", "--max-time", "2", METRICS + path))


def agent_config(path, interval, level="info", capacity=None):
    capacity_line = f"  map_capacity: {capacity}\n" if capacity is not None else ""
    path.write_text(f"""agent:
  interface: {IFACE}
  collect_interval: {interval}
{capacity_line}prometheus:
  listen_addr: '127.0.0.1:19090'
logging:
  level: {level}
  format: json
""")


def trial(args, left, right, workload, condition, raw, config):
    started = time.monotonic()
    binary = args.argus if condition == "enabled" else args.baseline_argus
    command = nscmd(left, binary, "-config", config) if binary else None
    try:
        with contextlib.ExitStack() as stack:
            agent = None
            if command:
                agent = stack.enter_context(process(command, raw / "agent.log", require_success=True, isolated_agent=True))
                wait_for(agent, lambda: curl(left, "/healthz") == "ok", "Argus")
            before = proc_sample(agent) if agent else None
            cpu_before = cpu_sample()
            if workload[0] == "http":
                measurement = nscmd(left, sys.executable, HTTP_LOAD, "client", SERVER, 18080,
                                   "--parallel", args.http_parallel, "--duration", args.duration,
                                   "--warmup", args.warmup)
            else:
                flags = ("-P", workload[1], *workload[2:]) if workload[0] == "tcp" else (
                    "-u", "-b", workload[1], "-l", args.udp_length)
                measurement = nscmd(left, "iperf3", "-c", SERVER, "-p", "15201", "-J",
                                    "-t", args.duration, "-O", args.warmup, *flags)
            dump(raw / "command.json", list(measurement))
            with (raw / "traffic.json").open("w") as stdout, (raw / "traffic.stderr").open("w") as stderr:
                subprocess.run(measurement, check=True, stdout=stdout, stderr=stderr,
                               timeout=args.warmup + args.duration + 25)
            cpu_after = cpu_sample()
            after = proc_sample(agent) if agent else None
            if agent:
                # Allow the last BPF snapshot to publish before taking evidence.
                time.sleep(args.collect_interval + 0.2)
                (raw / "metrics.txt").write_text(
                    "\n".join(line for line in curl(left, "/metrics").splitlines()
                              if line.startswith("network_")) + "\n"
                )
            result = json.loads((raw / "traffic.json").read_text())
            if workload[0] == "http":
                if not result["requests"] or result["errors"]:
                    raise ValueError("incomplete HTTP workload or HTTP request failures")
            else:
                received = result["end"]["sum_received"]
                if received["seconds"] < 0.9 * args.duration or received["bytes"] <= 0:
                    raise ValueError("incomplete iperf3 receiver measurement")
        dump(raw / "status.json", {
            "status": "ok",
            "wall_seconds": time.monotonic() - started,
            "proc_stat_cpu_delta": [end - start for start, end in zip(cpu_before, cpu_after)],
            "agent_before": before,
            "agent_after": after,
        })
    except BaseException as err:
        dump(raw / "status.json", {"status": "failed", "error": str(err)})
        raise


def validate(args):
    if platform.system() != "Linux" or os.geteuid() != 0:
        raise ValueError("run as root in an authorized Linux test environment")
    for tool in ("ip", "ss", "ethtool", "iperf3", "curl"):
        if not shutil.which(tool):
            raise ValueError(f"{tool} is required")
    if not args.argus.is_file() or not os.access(args.argus, os.X_OK):
        raise ValueError("--argus must point to an executable")
    baseline = getattr(args, "baseline_argus", None)
    if baseline and (not baseline.is_file() or not os.access(baseline, os.X_OK)):
        raise ValueError("--baseline-argus must point to an executable")
    versions = {tool: run(tool, flag).splitlines()[0] for tool, flag in
                (("ip", "-Version"), ("ethtool", "--version"), ("iperf3", "--version"), ("curl", "--version"))}
    if not versions["iperf3"].startswith(f"iperf {IPERF_VERSION} "):
        raise ValueError(f"iperf3 {IPERF_VERSION} is required")
    return versions


def main(args):
    versions = validate(args)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    raw = output / "raw"
    raw.mkdir()
    dump(output / "environment.json", {
        "platform": platform.platform(),
        "environment": args.environment,
        "cpu_count": os.cpu_count(),
        "memory": Path("/proc/meminfo").read_text().splitlines()[0],
        "cpu_ticks_per_second": os.sysconf("SC_CLK_TCK"),
        "tools": dict(versions, python=platform.python_version()),
        "source_revision": args.revision,
        "argus_sha256": hashlib.sha256(args.argus.read_bytes()).hexdigest(),
        "baseline": {
            "condition": "attached" if args.baseline_argus else "detached",
            "revision": args.baseline_revision or args.revision,
            "argus_sha256": hashlib.sha256(args.baseline_argus.read_bytes()).hexdigest()
            if args.baseline_argus else None,
        },
        "configuration": {key: str(value) if isinstance(value, Path) else value
                          for key, value in vars(args).items()},
        "topology": f"client namespace {CLIENT}/30 <-> veth <-> server namespace {SERVER}/30",
    })
    config = output / "agent.yaml"
    agent_config(config, f"{args.collect_interval}s")
    workloads = []
    if "tcp" in args.workloads:
        for streams, direction in itertools.product(args.tcp_streams, ("forward", "reverse")):
            flags = ("-R",) if direction == "reverse" else ()
            workloads.append((f"tcp-{streams}-{direction}", ("tcp", streams, *flags)))
    if "udp" in args.workloads:
        workloads.extend((f"udp-{rate}", ("udp", rate)) for rate in args.udp_rates)
    if "http" in args.workloads:
        workloads.append(("http", ("http",)))
    with topology(output) as (left, right), contextlib.ExitStack() as stack:
        if "tcp" in args.workloads or "udp" in args.workloads:
            iperf = stack.enter_context(process(nscmd(right, "iperf3", "-s", "-B", SERVER, "-p", 15201),
                                                raw / "iperf-server.log"))
            wait_for(iperf, lambda: listen_ready(right, 15201), "iperf3 server")
        if "http" in args.workloads:
            http = stack.enter_context(process(nscmd(right, sys.executable, HTTP_LOAD, "server", SERVER, 18080),
                                               raw / "http-server.log"))
            wait_for(http, lambda: listen_ready(right, 18080), "HTTP server")
        for name, workload in workloads:
            for repetition in range(1, args.repetitions + 1):
                order = ("baseline", "enabled") if repetition % 2 else ("enabled", "baseline")
                for condition in order:
                    label = f"{name}-{repetition:02d}-{condition}"
                    print(label, flush=True)
                    directory = raw / label
                    directory.mkdir()
                    trial(args, left, right, workload, condition, directory, config)
    dump(output / "status.json", {"status": "ok", "trials": len(workloads) * args.repetitions * 2})


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return number


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--argus", type=lambda s: Path(s).resolve(), required=True)
    parser.add_argument("--baseline-argus", type=lambda s: Path(s).resolve(),
                        help="attach this binary in baseline trials")
    parser.add_argument("--baseline-revision", help="required with --baseline-argus")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", required=True, help="tested Git revision, with -dirty if applicable")
    parser.add_argument("--environment", required=True, help="physical host, cloud VM, local VM, or emulator")
    parser.add_argument("--duration", type=positive, default=60)
    parser.add_argument("--warmup", type=positive, default=5)
    parser.add_argument("--repetitions", type=positive, default=5)
    parser.add_argument("--collect-interval", type=positive, default=5)
    parser.add_argument("--workloads", nargs="+", choices=("tcp", "udp", "http"), default=("tcp", "udp", "http"))
    parser.add_argument("--tcp-streams", nargs="+", type=positive, default=(1, 4))
    parser.add_argument("--udp-rates", nargs="+", default=("5M", "20M"))
    parser.add_argument("--udp-length", type=positive, default=1200)
    parser.add_argument("--http-parallel", type=positive, default=2)
    arguments = parser.parse_args()
    if bool(arguments.baseline_argus) != bool(arguments.baseline_revision):
        parser.error("--baseline-argus and --baseline-revision must be used together")
    if any(not re.fullmatch(r"[1-9][0-9]*[KMG]?", rate) for rate in arguments.udp_rates):
        parser.error("UDP rates must be integer bit/s, optionally with a K, M or G suffix")
    for candidates in (arguments.workloads, arguments.tcp_streams, arguments.udp_rates):
        if len(candidates) != len(set(candidates)):
            parser.error("duplicate workloads produce colliding result directories")
    signal.signal(signal.SIGTERM, lambda *_: signal.raise_signal(signal.SIGINT))
    try:
        main(arguments)
    except (Exception, KeyboardInterrupt) as error:
        print(f"benchmark failed: {error}", file=sys.stderr)
        sys.exit(1)
