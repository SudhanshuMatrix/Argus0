"""Small HTTP/1.1 workload for the private veth benchmark."""
import argparse
import array
import concurrent.futures
import http.client
import http.server
import json
import math
import time

BODY = b"x" * 64


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *_args):
        pass


def request_loop(address, port, measure, finish):
    samples = array.array("Q")
    errors = 0
    conn = http.client.HTTPConnection(address, port, timeout=2)
    try:
        while time.monotonic() < finish:
            start = time.monotonic_ns()
            try:
                conn.request("GET", "/")
                response = conn.getresponse()
                body = response.read()
                if response.status != 200 or body != BODY:
                    raise ValueError("unexpected HTTP response")
            except (OSError, http.client.HTTPException, ValueError):
                errors += int(start >= measure)
                conn.close()
            else:
                end = time.monotonic_ns()
                if start >= measure and end <= finish * 1e9:
                    samples.append(end - start)
    finally:
        conn.close()
    return samples, errors


def load(address, port, duration, warmup, parallel):
    measure = time.monotonic_ns() + warmup * 10**9
    finish = (measure + duration * 10**9) / 1e9
    cpu_start = time.process_time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as pool:
        futures = [pool.submit(request_loop, address, port, measure, finish) for _ in range(parallel)]
        results = [future.result() for future in futures]
    values = sorted(value for samples, _ in results for value in samples)
    print(json.dumps({
        "seconds": duration,
        "requests": len(values),
        "errors": sum(errors for _, errors in results),
        "requests_per_second": len(values) / duration,
        "client_cpu_seconds_including_warmup": time.process_time() - cpu_start,
        "latency_ms": {
            "p" + str(p): values[math.ceil(len(values) * p / 100) - 1] / 1e6
            for p in (50, 95, 99) if values
        },
    }))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("server", "client"))
    parser.add_argument("address")
    parser.add_argument("port", type=int)
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--warmup", type=int, default=5)
    parser.add_argument("--parallel", type=int, default=2)
    args = parser.parse_args()
    if args.mode == "server":
        http.server.ThreadingHTTPServer((args.address, args.port), Handler).serve_forever()
    else:
        load(args.address, args.port, args.duration, args.warmup, args.parallel)
