"""
Контекстный менеджер для синхронных tcpdump-захватов на нескольких
интерфейсах одного контейнера (в нашем случае r1: to-r2 и to-r3).

Использование:
    with Capture(interfaces=["to-r2", "to-r3"],
                 bpf="ip and dst host 10.0.2.10",
                 output_dir=tmp_path) as pcaps:
        send_from_h1(count=1000, strategy="random")
"""

from __future__ import annotations

import os
import select
import subprocess
import time
from pathlib import Path
from typing import IO


CAPTURE_READY_TIMEOUT_S = 10  # максимум ждём баннер "listening on" от tcpdump
CAPTURE_DRAIN_S = 0.5         # дать tcpdump'у поймать последние пакеты
TCPDUMP_MAX_DURATION_S = 60

_LISTENING_MARKER = b"listening on"


class Capture:
    def __init__(
        self,
        *,
        interfaces: list[str],
        bpf: str,
        output_dir: Path,
        container: str = "r1",
        max_duration_s: float = TCPDUMP_MAX_DURATION_S,
    ) -> None:
        self.container = container
        self.interfaces = interfaces
        self.bpf = bpf
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.max_duration_s = max_duration_s
        self._procs: dict[str, subprocess.Popen] = {}
        self._files: dict[str, IO[bytes]] = {}
        self._pcaps: dict[str, Path] = {}

    def __enter__(self) -> dict[str, Path]:
        # На случай зомби-процессов от прошлого прогона.
        subprocess.run(
            ["docker", "exec", self.container, "pkill", "-x", "tcpdump"],
            capture_output=True, check=False,
        )
        for iface in self.interfaces:
            pcap = self.output_dir / f"{self.container}-{iface}.pcap"
            self._pcaps[iface] = pcap
            f = pcap.open("wb")
            self._files[iface] = f
            cmd = [
                "docker", "exec", self.container,
                "timeout", str(self.max_duration_s),
                "tcpdump", "-i", iface, "-U", "-n", "-w", "-", self.bpf,
            ]
            self._procs[iface] = subprocess.Popen(
                cmd, stdout=f, stderr=subprocess.PIPE,
            )
        self._wait_until_listening()
        return self._pcaps

    def _wait_until_listening(self) -> None:
        pending: dict[str, bytes] = {iface: b"" for iface in self._procs}
        fd_to_iface = {
            proc.stderr.fileno(): iface
            for iface, proc in self._procs.items()
        }
        deadline = time.monotonic() + CAPTURE_READY_TIMEOUT_S

        while pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    "tcpdump not ready on interfaces "
                    f"{CAPTURE_READY_TIMEOUT_S}s: {sorted(pending)}"
                )
            ready_fds = [self._procs[i].stderr.fileno() for i in pending]
            rlist, _, _ = select.select(ready_fds, [], [], remaining)
            if not rlist:
                continue
            for fd in rlist:
                iface = fd_to_iface[fd]
                chunk = os.read(fd, 4096)
                if not chunk:
                    raise RuntimeError(
                        f"tcpdump on {iface} terminated before capture started: "
                        f"{pending[iface].decode(errors='replace').strip()!r}"
                    )
                pending[iface] += chunk
                if _LISTENING_MARKER in pending[iface]:
                    del pending[iface]

    def __exit__(self, exc_type, exc, tb) -> bool:
        time.sleep(CAPTURE_DRAIN_S)
        subprocess.run(
            ["docker", "exec", self.container, "pkill", "-INT", "-x", "tcpdump"],
            capture_output=True, check=False,
        )
        for proc in self._procs.values():
            try:
                if proc.stderr is not None:
                    proc.stderr.read()
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
            finally:
                if proc.stderr is not None:
                    proc.stderr.close()
        for f in self._files.values():
            f.close()
        return False
