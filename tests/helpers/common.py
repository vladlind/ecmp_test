"""
Общие константы и хелперы для всех ECMP-тестов.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import allure

# H2 = единственный получатель тестового трафика; BPF-фильтр у tcpdump'а
# вырезает всё кроме него (отсеивает OSPF Hello, ARP и прочее).
H2_IP = "10.0.2.10"
DEFAULT_BPF = f"ip and dst host {H2_IP}"

# ECMP-маршрут на R1: подсеть H2 и два nexthop'а (R2, R3).
ECMP_DEST_NET = "10.0.2.0/24"
ECMP_NEXTHOPS = ("10.0.12.2", "10.0.13.2")

# Два ECMP-интерфейса R1, через которые ходит трафик к H2.
ECMP_INTERFACES = ["to-r2", "to-r3"]


def exec_in(container: str, cmd: str, sh: str = "sh", *, timeout: float = 30.0) -> subprocess.CompletedProcess:
    """`docker exec <container> sh -c '<cmd>'` без проверки exit code."""
    return subprocess.run(
        ["docker", "exec", container, sh, "-c", cmd],
        capture_output=True, text=True, timeout=timeout,
    )


def exec_in_check(container: str, cmd: str, *, timeout: float = 30.0) -> str:
    """То же, но падает при rc != 0; возвращает stdout."""
    r = exec_in(container, cmd, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(
            f"docker exec {container} failed (rc={r.returncode}):\n"
            f"  cmd:    {cmd}\n"
            f"  stdout: {r.stdout.strip()}\n"
            f"  stderr: {r.stderr.strip()}"
        )
    return r.stdout

def attach_pcaps(pcaps: dict[str, Path], *, suffix: str = "") -> None:
    """Прикрепляет каждый непустой pcap к текущему Allure-тесту."""
    for iface, p in pcaps.items():
        if p.exists() and p.stat().st_size > 0:
            allure.attach.file(
                str(p), name=f"r1-{iface}{suffix}.pcap", extension="pcap",
            )
