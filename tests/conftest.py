"""
Сессионная фикстура `topology`: проверяет, что все контейнеры подняты и OSPF
сошёлся (ECMP-маршрут из 2-х nexthop'ов виден на R1). Если нет — fail с
понятным сообщением, что нужно прогнать ./run.sh.
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass

import pytest

from helpers.common import ECMP_DEST_NET, ECMP_NEXTHOPS, exec_in

EXPECTED_CONTAINERS = ("h1", "h2", "r1", "r2", "r3", "r4")
CONVERGENCE_TIMEOUT_S = 30


@dataclass
class Topology:
    ecmp_dest: str
    ecmp_nexthops: tuple[str, ...]


def _running_containers() -> set[str]:
    r = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"],
        capture_output=True, text=True, check=True, timeout=10,
    )
    return set(r.stdout.strip().splitlines())


def _wait_for_ecmp(deadline: float) -> int:
    """Возвращает число nexthop'ов на R1 для ECMP_DEST_NET (последнее увиденное)."""
    nh = 0
    while time.time() < deadline:
        out = exec_in("r1", f"ip route show {ECMP_DEST_NET}").stdout
        nh = out.count("nexthop")
        if nh >= 2:
            return nh
        time.sleep(1)
    return nh


@pytest.fixture(scope="session")
def topology() -> Topology:
    """
    Гарантирует, что стенд готов к тестам:
      1. Все 6 контейнеров запущены.
      2. На R1 установлен ECMP-маршрут к подсети H2 с >=2 nexthop'ами
    """
    running = _running_containers()
    missing = set(EXPECTED_CONTAINERS) - running
    if missing:
        pytest.fail(
            f"Не запущены контейнеры: {sorted(missing)}. "
            f"Прогоните `./run.sh` из корня репозитория.",
            pytrace=False,
        )

    nh = _wait_for_ecmp(time.time() + CONVERGENCE_TIMEOUT_S)
    if nh < 2:
        pytest.fail(
            f"OSPF не сошёлся за {CONVERGENCE_TIMEOUT_S}s — "
            f"на R1 для {ECMP_DEST_NET} только {nh} nexthop'ов (ожидалось >=2). "
            f"Проверьте `docker exec r1 vtysh -c 'show ip ospf neighbor'`.",
            pytrace=False,
        )

    return Topology(
        ecmp_dest=ECMP_DEST_NET,
        ecmp_nexthops=ECMP_NEXTHOPS,
    )
