"""
Session fixture `topology`: verifies that all containers are up and OSPF has
converged (an ECMP route with 2 nexthops is visible on R1). If not — fail with
a clear message that ./run.sh needs to be run.
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
    """Returns the number of nexthops on R1 for ECMP_DEST_NET (last seen)."""
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
    Ensures the testbed is ready for the tests:
      1. All 6 containers are running.
      2. R1 has an ECMP route to the H2 subnet with >=2 nexthops.
    """
    running = _running_containers()
    missing = set(EXPECTED_CONTAINERS) - running
    if missing:
        pytest.fail(
            f"Containers not running: {sorted(missing)}. "
            f"Run `./run.sh` from the repository root.",
            pytrace=False,
        )

    nh = _wait_for_ecmp(time.time() + CONVERGENCE_TIMEOUT_S)
    if nh < 2:
        pytest.fail(
            f"OSPF did not converge within {CONVERGENCE_TIMEOUT_S}s — "
            f"R1 has only {nh} nexthops for {ECMP_DEST_NET} (expected >=2). "
            f"Check `docker exec r1 vtysh -c 'show ip ospf neighbor'`.",
            pytrace=False,
        )

    return Topology(
        ecmp_dest=ECMP_DEST_NET,
        ecmp_nexthops=ECMP_NEXTHOPS,
    )
