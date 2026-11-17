"""Summarize successful paired trials from a run.py output directory."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import statistics

from run import dump


def load(path):
    return json.loads(path.read_text())


def distribution(values):
    return {
        "median": statistics.median(values),
        "mean": statistics.mean(values),
        "min": min(values),
        "max": max(values),
        "sample_stddev": statistics.stdev(values) if len(values) > 1 else None,
    }


def trial(path, clock_ticks):
    status = load(path / "status.json")
    if status["status"] != "ok":
        raise ValueError(f"unsuccessful trial {path.name}: {status}")
    source = load(path / "traffic.json")
    values = {}
    if path.name.startswith("http-"):
        values["requests_per_second"] = source["requests_per_second"]
        values["error_percent"] = 100 * source["errors"] / (source["requests"] + source["errors"])
        values.update({key + "_ms": value for key, value in source["latency_ms"].items()})
        values["receiver_seconds"] = source["seconds"]
    else:
        received = source["end"]["sum_received"]
        values["receiver_mbps"] = received["bits_per_second"] / 1e6
        values["receiver_seconds"] = received["seconds"]
        cpu = source["end"]["cpu_utilization_percent"]
        values["iperf_client_cpu_percent"] = cpu["host_total"]
        values["iperf_server_cpu_percent"] = cpu["remote_total"]
        if path.name.startswith("udp-"):
            values["receiver_loss_percent"] = received["lost_percent"]
            values["receiver_lost_packets"] = received["lost_packets"]
            values["receiver_jitter_ms"] = received["jitter_ms"]
        else:
            values["retransmissions"] = source["end"]["sum_sent"]["retransmits"]
    cpu = status["proc_stat_cpu_delta"]
    total = sum(cpu[:8])
    if total:
        values["guest_kernel_cpu_percent"] = 100 * (cpu[2] + cpu[5] + cpu[6]) / total
        values["guest_steal_percent"] = 100 * cpu[7] / total
    before, after = status["agent_before"], status["agent_after"]
    if before and after:
        elapsed = after["monotonic_seconds"] - before["monotonic_seconds"]
        values["argus_process_cpu_percent_of_one_vcpu"] = 100 * (
            after["cpu_ticks"] - before["cpu_ticks"]
        ) / (clock_ticks * elapsed)
        values["argus_rss_kib_after"] = after["rss_kib"]
    return values


def summarize(root):
    status = load(root / "status.json")
    if status["status"] != "ok":
        raise ValueError(f"unsuccessful run: {status}")
    environment = load(root / "environment.json")
    repetitions = environment["configuration"]["repetitions"]
    paired = defaultdict(lambda: defaultdict(dict))
    count = 0
    for directory in sorted((root / "raw").iterdir()):
        if not directory.is_dir():
            continue
        name, repetition, condition = directory.name.rsplit("-", 2)
        paired[name][condition][int(repetition)] = trial(directory, environment["cpu_ticks_per_second"])
        count += 1
    if count != status["trials"]:
        raise ValueError(f"trial count {count} differs from run status {status['trials']}")
    data = {}
    for name, groups in paired.items():
        baseline, enabled = groups["baseline"], groups["enabled"]
        if set(baseline) != set(range(1, repetitions + 1)) or set(enabled) != set(baseline):
            raise ValueError(f"incomplete pairing for {name}")
        case = {}
        for condition, runs in groups.items():
            keys = next(iter(runs.values())).keys()
            case[condition] = {key: distribution([values[key] for values in runs.values()]) for key in keys}
        overhead = {}
        for key in baseline[1]:
            if key in ("receiver_mbps", "requests_per_second", "p50_ms", "p95_ms", "p99_ms"):
                sign = 1 if key.endswith("_ms") else -1
                b, e = case["baseline"][key]["median"], case["enabled"][key]["median"]
                overhead[key] = {
                    "percent_difference_of_medians": sign * 100 * (e - b) / b,
                    "paired_percent_differences": distribution([
                        sign * 100 * (enabled[index][key] - flags[key]) / flags[key]
                        for index, flags in baseline.items()
                    ]),
                }
        case["overhead"] = overhead
        data[name] = case
    return {
        "trials": count,
        "baseline": environment.get("baseline", {"condition": "detached"}),
        "repetitions_per_condition": repetitions,
        "source_revision": environment["source_revision"],
        "workloads": data,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    dump(args.output, summarize(args.directory))
