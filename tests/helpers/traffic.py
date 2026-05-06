"""
Генерирует трафик из h1 через `docker exec`.
Реальный отправитель — h1_send.py, монтируется в h1 как /helpers/h1_send.py.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Literal


H1_CONTAINER = "h1"
H1_SCRIPT = "/helpers/h1_send.py"
H1_SRCS_FILE = "/tmp/sent_srcs.txt"


Strategy = Literal["single", "sequential", "random", "sparse", "edges"]


def send_from_h1(
    *,
    count: int,
    dst: str = "10.0.2.10",
    strategy: Strategy = "single",
    src: str = "10.0.1.10",
    src_base: str = "10.99.0.0/16",
    timeout: float = 60.0,
    proto: str = "ICMP"
) -> list[str]:
    cmd = [
        "docker", "exec", H1_CONTAINER,
        "python3", H1_SCRIPT,
        "--count", str(count),
        "--dst", dst,
        "--strategy", strategy,
        "--src", src,
        "--src-base", src_base,
        "--output-srcs", H1_SRCS_FILE,
        "--proto", proto
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(
            f"send_from_h1 failed (rc={r.returncode}):\n"
            f"  cmd:    {' '.join(cmd)}\n"
            f"  stdout: {r.stdout.strip()}\n"
            f"  stderr: {r.stderr.strip()}"
        )

    cat = subprocess.run(
        ["docker", "exec", H1_CONTAINER, "cat", H1_SRCS_FILE],
        capture_output=True, text=True, check=True, timeout=10,
    )
    return [line for line in cat.stdout.splitlines() if line]
