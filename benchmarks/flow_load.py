"""Send fixed-size UDP payloads from distinct source ports in the test namespace."""
import argparse
import json
import os
from pathlib import Path
import socket
import time

from run import CLIENT, SERVER


def send(start, count, destination):
    payload = b"f" * 32
    started = time.monotonic()
    for port in range(start, start + count):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((CLIENT, port))
            if sock.sendto(payload, (SERVER, destination)) != len(payload):
                raise RuntimeError("short UDP send")
    print(json.dumps({"sender_pid": os.getpid(), "packets_sent": count,
                      "payload_bytes": len(payload), "seconds": time.monotonic() - started}))


def receive(port, outfile):
    # Flush progress periodically so the parent can query it after traffic stops.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((SERVER, port))
        sock.settimeout(0.2)
        packets = 0
        path = Path(outfile)
        temporary = path.with_suffix(".tmp")
        path.write_text("0\n")
        while True:
            try:
                sock.recv(2048)
                packets += 1
            except socket.timeout:
                temporary.write_text(str(packets) + "\n")
                temporary.replace(path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("send", "receive"))
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--start", type=int)
    parser.add_argument("--count", type=int)
    parser.add_argument("--outfile")
    args = parser.parse_args()
    if args.mode == "send":
        send(args.start, args.count, args.port)
    else:
        receive(args.port, args.outfile)
