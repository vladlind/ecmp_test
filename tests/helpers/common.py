"""
Общие константы и хелперы для всех ECMP-тестов.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import allure

from .capture import Capture
from .traffic import send_from_h1

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
    for iface, p in pcaps.items():
        if p.exists() and p.stat().st_size > 0:
            allure.attach.file(
                str(p), name=f"r1-{iface}{suffix}.pcap", extension="pcap",
            )


DEFAULT_BALANCE_TOLERANCE = 0.1
DEFAULT_MIN_CAPTURE_RATIO = 0.95


def run_test_traffic(
    *,
    output_dir: Path,
    count: int,
    strategy: str,
    interfaces: list[str] | None = None,
    bpf: str = DEFAULT_BPF,
    container: str = "r1",
    pcap_suffix: str = "",
    step_label: str | None = None,
    **send_kwargs: Any,
) -> tuple[dict[str, Path], list[str]]:
    """
    Запустить tcpdump на интерфейсах + send_from_h1 + attach_pcaps.
    Возвращает (pcaps, sent_srcs).
    """
    if interfaces is None:
        interfaces = ECMP_INTERFACES
    if step_label is None:
        proto = send_kwargs.get("proto", "ICMP")
        step_label = (
            f"Захват на {container} ({', '.join(interfaces)}) + "
            f"отправка {count} {proto} ({strategy})"
        )
    with allure.step(step_label):
        with Capture(
            interfaces=interfaces, bpf=bpf, output_dir=output_dir, container=container,
        ) as pcaps:
            sent = send_from_h1(count=count, strategy=strategy, **send_kwargs)
    attach_pcaps(pcaps, suffix=pcap_suffix)
    return pcaps, sent


def assert_no_capture_loss(
    totals: dict[str, int],
    n_sent: int,
    *,
    min_ratio: float = DEFAULT_MIN_CAPTURE_RATIO,
    context: str = "",
) -> None:
    captured = sum(totals.values())
    prefix = f"[{context}] " if context else ""
    assert captured >= int(n_sent * min_ratio), (
        f"{prefix}Захвачено {captured}/{n_sent} (<{min_ratio*100:.0f}%) — "
        f"потери или баг захвата:\n{totals}"
    )


def assert_balanced(
    ratios: dict[str, float],
    totals: dict[str, int],
    *,
    tolerance: float = DEFAULT_BALANCE_TOLERANCE,
    context: str = "",
) -> None:
    prefix = f"[{context}] " if context else ""
    for iface, p in ratios.items():
        assert abs(p - 0.5) < tolerance, (
            f"{prefix}Дисбаланс на {iface}: доля {p:.3f} "
            f"(ожидалось 0.5 ± {tolerance}). Полные счётчики: {totals}"
        )


def attach_distribution_summary(
    totals: dict[str, int],
    ratios: dict[str, float],
    *,
    name: str = "distribution summary",
    **extra: Any,
) -> None:
    lines = [f"{k}: {v}" for k, v in extra.items()]
    lines.append(f"пакетов на интерфейсах: {totals}")
    lines.append(
        f"баланс:    { {k: round(v, 4) for k, v in ratios.items()} }"
    )
    allure.attach(
        "\n".join(lines), name=name, attachment_type=allure.attachment_type.TEXT,
    )
