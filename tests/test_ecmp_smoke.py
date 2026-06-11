"""
Scenario #1: smoke — the ECMP route is installed in R1's FIB, both nexthops are
present, and H1 can reach H2.
"""

import allure
import pytest

from helpers.common import exec_in_check

pytestmark = [
    pytest.mark.smoke,
    allure.epic("ECMP Source-IP hashing"),
    allure.feature("FIB / convergence")
]


@allure.story("Verify ECMP works - there must be two routes")
@allure.severity(allure.severity_level.BLOCKER)
@allure.title("R1 sees both nexthops to the H2 subnet")
def test_ecmp_route_has_two_nexthops_on_r1(topology):
    out = exec_in_check("r1", f"ip route show {topology.ecmp_dest}")
    allure.attach(out, name="ip route show", attachment_type=allure.attachment_type.TEXT)
    for nh in topology.ecmp_nexthops:
        assert nh in out, (
            f"Expected nexthop {nh} not found in the route to {topology.ecmp_dest}:\n{out}"
        )
    assert out.count("nexthop") >= 2, f"Expected >=2 nexthops, got:\n{out}"

@allure.story("Verify network connectivity over the ECMP routes")
@allure.severity(allure.severity_level.BLOCKER)
@allure.title("H1 pings H2 over the ECMP route")
def test_h1_can_reach_h2(topology):
    out = exec_in_check("h1", "ping -c 3 -W 2 10.0.2.10")
    allure.attach(out, name="ping output", attachment_type=allure.attachment_type.TEXT)
    assert "0% packet loss" in out, f"H1 could not reach H2:\n{out}"
