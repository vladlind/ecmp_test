"""
Shared constants and helpers for all ECMP tests.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import allure

from .capture import Capture
from .traffic import send_from_h1

# H2 = the only recipient of test traffic; tcpdump's BPF filter cuts out
# everything else (filters out OSPF Hello, ARP, etc.).
H2_IP = "10.0.2.10"
DEFAULT_BPF = f"ip and dst host {H2_IP}"

# ECMP route on R1: the H2 subnet and two nexthops (R2, R3).
ECMP_DEST_NET = "10.0.2.0/24"
ECMP_NEXTHOPS = ("10.0.12.2", "10.0.13.2")

# The two ECMP interfaces on R1 that carry traffic to H2.
ECMP_INTERFACES = ["to-r2", "to-r3"]


def exec_in(container: str, cmd: str, sh: str = "sh", *, timeout: float = 30.0) -> subprocess.CompletedProcess:
    """`docker exec <container> sh -c '<cmd>'` without checking the exit code."""
    return subprocess.run(
        ["docker", "exec", container, sh, "-c", cmd],
        capture_output=True, text=True, timeout=timeout,
    )


def exec_in_check(container: str, cmd: str, *, timeout: float = 30.0) -> str:
    """Same, but raises on rc != 0; returns stdout."""
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
    Run tcpdump on the interfaces + send_from_h1 + attach_pcaps.
    Returns (pcaps, sent_srcs).
    """
    if interfaces is None:
        interfaces = ECMP_INTERFACES
    if step_label is None:
        proto = send_kwargs.get("proto", "ICMP")
        step_label = (
            f"Capture on {container} ({', '.join(interfaces)}) + "
            f"sending {count} {proto} ({strategy})"
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
        f"{prefix}Captured {captured}/{n_sent} (<{min_ratio*100:.0f}%) — "
        f"packet loss or a capture bug:\n{totals}"
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
            f"{prefix}Imbalance on {iface}: ratio {p:.3f} "
            f"(expected 0.5 ± {tolerance}). Full counters: {totals}"
        )


def attach_distribution_summary(
    totals: dict[str, int],
    ratios: dict[str, float],
    *,
    name: str = "distribution summary",
    **extra: Any,
) -> None:
    lines = [f"{k}: {v}" for k, v in extra.items()]
    lines.append(f"packets per interface: {totals}")
    lines.append(
        f"balance:    { {k: round(v, 4) for k, v in ratios.items()} }"
    )
    allure.attach(
        "\n".join(lines), name=name, attachment_type=allure.attachment_type.TEXT,
    )
