"""
Scenario #7: Link failure — failover to the remaining path.

In the first test:
We bring to-r2 down on R1 (`ip link set to-r2 down`), wait for OSPF to remove
the nexthop via R2, then send traffic with various Src IPs. We check:
  (a) the ECMP route on R1 now has a single nexthop (via R3);
  (b) no packet is lost after convergence (>=99% of those sent are caught on R1);
  (c) 100% of the caught traffic went through to-r3.

In the second test:
We bring the interface back up and wait for ECMP to recover, to verify
balancing across both nexthops (each should receive roughly half of the traffic).
"""

from __future__ import annotations

import time

import allure
import pytest

from helpers.common import (
    ECMP_DEST_NET,
    H2_IP,
    assert_balanced,
    assert_no_capture_loss,
    attach_distribution_summary,
    exec_in,
    exec_in_check,
    run_test_traffic,
)
from helpers.analyzer import balance_ratio, total_per_iface


N_PACKETS = 500
RECONVERGE_TIMEOUT_S = 60    # we wait long, since frr has to be restarted - see comment below
DOWN_NEXTHOP = "10.0.12.2"   # via R2 — must disappear
ALIVE_NEXTHOP = "10.0.13.2"  # via R3 — must remain

pytestmark = [
    pytest.mark.distribution,
    allure.epic("ECMP Source-IP hashing"),
    allure.feature("Link failure"),
]

"""
Wrapper around a boolean function with a timeout - run the function within the
timeout until it returns true.
"""
def _wait_until(predicate, timeout_s: float, poll_s: float = 1.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(poll_s)
    return predicate()


def _route_via_r3_only() -> bool:
    out = exec_in("r1", f"ip route show {ECMP_DEST_NET}").stdout
    return ALIVE_NEXTHOP in out and DOWN_NEXTHOP not in out

def _route_via_r2_and_r3() -> bool:
    out = exec_in("r1", f"ip route show {ECMP_DEST_NET}").stdout
    return ALIVE_NEXTHOP in out and DOWN_NEXTHOP in out

def _route_has_ecmp() -> bool:
    out = exec_in("r1", f"ip route show {ECMP_DEST_NET}").stdout
    return out.count("nexthop") >= 2


@pytest.fixture(scope="module")
def to_r2_down(topology):
    """
    Brings to-r2 down on R1, waits for OSPF to converge onto a single nexthop
    via R3. On teardown brings the interface back up and waits until the ECMP
    route with >=2 nexthops returns.
    """
    exec_in_check("r1", "ip link set to-r2 down")
    try:
        if not _wait_until(_route_via_r3_only, RECONVERGE_TIMEOUT_S):
            out = exec_in("r1", f"ip route show {ECMP_DEST_NET}").stdout
            pytest.fail(
                f"OSPF did not drop the nexthop via R2 within {RECONVERGE_TIMEOUT_S}s. "
                f"Current route on R1:\n{out}",
                pytrace=False,
            )
        yield
    finally:
        if not _route_has_ecmp():
            out = exec_in("r1", f"ip route show {ECMP_DEST_NET}").stdout
            pytest.fail(
                f"After bringing to-r2 up, ECMP did not recover within "
                f"{RECONVERGE_TIMEOUT_S}s. Route on R1:\n{out}",
                pytrace=False,
            )

@pytest.mark.order(1)
@allure.story("After one of the links goes down, traffic takes the remaining path")
@allure.severity(allure.severity_level.CRITICAL)
@allure.title("to-r2 down: route collapses to R3, all traffic goes via R3, no loss")
def test_link_failure_falls_back_to_remaining_path(to_r2_down, tmp_path):
    route_after_down = exec_in("r1", f"ip route show {ECMP_DEST_NET}").stdout
    allure.attach(
        route_after_down,
        name="r1 route after to-r2 down",
        attachment_type=allure.attachment_type.TEXT,
    )
    assert ALIVE_NEXTHOP in route_after_down and DOWN_NEXTHOP not in route_after_down, (
        f"Expected a single nexthop via {ALIVE_NEXTHOP}, actual:\n{route_after_down}"
    )
    assert route_after_down.count("nexthop") <= 1, (
        f"Route is still multipath after to-r2 went down:\n{route_after_down}"
    )

    pcaps, sent = run_test_traffic(
        output_dir=tmp_path, count=N_PACKETS, strategy="random",
        interfaces=["to-r3"],
    )

    totals = total_per_iface(pcaps, dst_ip=H2_IP)
    allure.attach(
        f"sent: {len(sent)}\ncaptured per iface: {totals}",
        name="link-failure summary",
        attachment_type=allure.attachment_type.TEXT,
    )

    assert_no_capture_loss(totals, N_PACKETS, min_ratio=0.99, context="after to-r2 down")
    captured = sum(totals.values())
    assert totals.get("to-r3", 0) == captured, (
        f"Not all captured traffic went through to-r3: {totals}"
    )

@pytest.mark.order(2)
@allure.story("After the link recovers - traffic is balanced again")
@allure.severity(allure.severity_level.CRITICAL)
@allure.title("to-r2 up: route recovers and balances across the two nexthops")
def test_link_recovery_balances_between_paths(to_r2_down, tmp_path):
    exec_in("r1", "ip link set to-r2 up")
    """
    The frr restart is forced - after the link comes back up, zebra for some
    reason does not accept the recovered multi-hop route from ospf.
    Looks like the issue described in the bug report - https://github.com/FRRouting/frr/issues/15505
    """
    exec_in("r1", "/usr/lib/frr/frrinit.sh restart")

    if not _wait_until(_route_via_r2_and_r3, RECONVERGE_TIMEOUT_S):
        routes_after_up = exec_in("r1", f"ip route show {ECMP_DEST_NET}").stdout
        ospf_rib_after_up = exec_in("r1", f"show ip route ospf {ECMP_DEST_NET}", "vtysh").stdout
        pytest.fail(
            f"the nexthop via R2 did not return within {RECONVERGE_TIMEOUT_S}s. "
            f"Current route on R1:\n{routes_after_up}"
            f"OSPF RIB on R1:\n{ospf_rib_after_up}",
            pytrace=False,
        )

    routes_after_up = exec_in("r1", f"ip route show {ECMP_DEST_NET}").stdout

    allure.attach(
        routes_after_up,
        name="r1 route after to-r2 is up",
        attachment_type=allure.attachment_type.TEXT,
    )

    pcaps_after, sent = run_test_traffic(
        output_dir=tmp_path, count=N_PACKETS, strategy="random",
        interfaces=["to-r2", "to-r3"],
    )

    totals_after = total_per_iface(pcaps_after, dst_ip=H2_IP)
    ratios = balance_ratio(pcaps_after, dst_ip=H2_IP)

    attach_distribution_summary(
        totals_after, ratios,
        name="distribution summary after recovery",
        sent=len(sent),
    )
    assert_balanced(ratios, totals_after, context="after recovery")
