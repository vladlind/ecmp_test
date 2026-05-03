#!/usr/bin/env python3
"""
Запускается ВНУТРИ контейнера h1. Шлёт ICMP-эхо к фиксированному dst,
варьируя Source IP по выбранной стратегии.

Стратегии Src IP:
  single      — все пакеты с одного --src
  sequential  — берёт последовательные адреса из --src-base
  random      — случайные адреса из --src-base
  edges       — берет крайние адреса --src-base (network и broadcast)
"""

from __future__ import annotations

import argparse
import ipaddress
import random
import sys

from scapy.all import IP, ICMP, send, conf

conf.verb = 0

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
        rnd = random.Random(0xECF1)  # повторяемость случайного ряда
        return [str(rnd.choice(pool)) for _ in range(count)]
    raise ValueError(f"Unknown strategy: {strategy}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--count", type=int, required=True)
    ap.add_argument("--dst", default="10.0.2.10")
    ap.add_argument("--strategy", choices=["single", "sequential", "random", "edges"], default="single")
    ap.add_argument("--src", default="10.0.1.10")
    ap.add_argument("--src-base", default="10.99.0.0/16")
    ap.add_argument("--output-srcs", default="/tmp/sent_srcs.txt")
    args = ap.parse_args()

    src_ips = gen_src_ips(args.strategy, args.count, args.src, args.src_base)
    packets = [
        IP(src=s, dst=args.dst) / ICMP(type=8, id=0xBEEF, seq=i & 0xFFFF)
        for i, s in enumerate(src_ips)
    ]
    send(packets, verbose=False, inter=0)

    with open(args.output_srcs, "w") as f:
        f.write("\n".join(src_ips))

    print(f"sent {len(packets)} packets ({args.strategy})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
