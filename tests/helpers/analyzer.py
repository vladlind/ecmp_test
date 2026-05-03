"""
Анализ pcap'ов из Capture.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path

from scapy.all import rdpcap, IP


def _iter_ip(pcap: Path, dst_ip: str | None):
    for pkt in rdpcap(str(pcap)):
        if IP not in pkt:
            continue
        ip = pkt[IP]
        if dst_ip is not None and ip.dst != dst_ip:
            continue
        yield ip


def total_per_iface(pcaps: dict[str, Path], dst_ip: str | None = None) -> dict[str, int]:
    """Сколько IP-пакетов (с нужным dst) в каждом интерфейсе."""
    return {iface: sum(1 for _ in _iter_ip(p, dst_ip)) for iface, p in pcaps.items()}


def count_by_src_per_iface(
    pcaps: dict[str, Path], dst_ip: str | None = None
) -> dict[str, Counter]:
    result: dict[str, Counter] = {}
    for iface, p in pcaps.items():
        c: Counter = Counter()
        for ip in _iter_ip(p, dst_ip):
            c[ip.src] += 1
        result[iface] = c
    return result


def src_ip_to_ifaces(
    pcaps: dict[str, Path], dst_ip: str | None = None
) -> dict[str, set[str]]:
    """
    Для каждого Src IP — множество интерфейсов, на которых он замечен.
    Для корректного ECMP с stickiness каждый Src IP должен попасть строго
    на один интерфейс (set размера 1).
    """
    result: dict[str, set[str]] = defaultdict(set)
    for iface, p in pcaps.items():
        for ip in _iter_ip(p, dst_ip):
            result[ip.src].add(iface)
    return dict(result)


def balance_ratio(pcaps: dict[str, Path], dst_ip: str | None = None) -> dict[str, float]:
    totals = total_per_iface(pcaps, dst_ip)
    grand = sum(totals.values()) or 1
    return {iface: n / grand for iface, n in totals.items()}

