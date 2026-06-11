#!/usr/bin/env python3
"""
Runs INSIDE the h1 container. Sends ICMP echo to a fixed dst,
varying the Source IP according to the chosen strategy.

Src IP strategies:
  single      — all packets from a single --src
  sequential  — takes consecutive addresses from --src-base
  random      — random addresses from --src-base
  sparse      — evenly spread addresses across the whole address pool
  edges       — takes the edge addresses of --src-base (network and broadcast)
"""

from __future__ import annotations

import argparse
import ipaddress
import random
import sys

from scapy.all import IP, ICMP, UDP, TCP, Raw, send, conf

conf.verb = 0

rnd = random.Random(0xECF1)  # reproducible random sequence

def gen_src_ips(strategy: str, count: int, src: str, src_base: str) -> list[str]:
    if strategy == "single":
        return [src] * count
    base = ipaddress.IPv4Network(src_base, strict=False)
    if strategy == "edges":
        edges = [str(base.network_address), str(base.broadcast_address)]
        return [edges[i % 2] for i in range(count)]
    pool = list(base.hosts())
    if not pool:
        raise ValueError(f"Empty IP pool from {src_base}")
    if strategy == "sequential":
        return [str(pool[i % len(pool)]) for i in range(count)]
    if strategy == "random":
        return [str(ip) for ip in rnd.sample(pool, count)]
    if strategy == "sparse":
        step = max(1, len(pool) // count)
        return [str(pool[(i * step) % len(pool)]) for i in range(count)]
    raise ValueError(f"Unknown strategy: {strategy}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--count", type=int, required=True)
    ap.add_argument("--dst", default="10.0.2.10")
    ap.add_argument("--strategy", choices=["single", "sequential", "random", "sparse", "edges"], default="single")
    ap.add_argument("--src", default="10.0.1.10")
    ap.add_argument("--src-base", default="10.99.0.0/16")
    ap.add_argument("--output-srcs", default="/tmp/sent_srcs.txt")
    ap.add_argument("--proto", default="ICMP")
    args = ap.parse_args()

    src_ips = gen_src_ips(args.strategy, args.count, args.src, args.src_base)

    def rand_sport() -> int:
        return rnd.randint(1025, 65535)

    def l4(i: int):
        if args.proto == "UDP":
            return UDP(sport=rand_sport(), dport=123) / Raw(load="abc")
        if args.proto == "TCP":
            return TCP(sport=rand_sport(), dport=445, flags="S")
        return ICMP(type=8, id=0xBEEF, seq=i & 0xFFFF)

    packets = [
        IP(src=s, dst=args.dst) / l4(i)
        for i, s in enumerate(src_ips)
    ]
    send(packets, verbose=False, inter=0)

    with open(args.output_srcs, "w") as f:
        f.write("\n".join(src_ips))

    print(f"sent {len(packets)} packets ({args.strategy})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
