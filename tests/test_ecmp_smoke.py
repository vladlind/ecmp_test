"""
Сценарий #1: smoke — ECMP-маршрут установлен в FIB R1, оба nexthop'а на месте,
H1 может достучаться до H2.
"""

import allure
import pytest

from helpers.common import exec_in_check

pytestmark = [
    pytest.mark.smoke,
    allure.epic("ECMP Source-IP hashing"),
    allure.feature("FIB / convergence")
]


@allure.story("Проверка работы ECMP - должно быть два маршрута")
@allure.severity(allure.severity_level.BLOCKER)
@allure.title("R1 видит оба nexthop'а к подсети H2")
def test_ecmp_route_has_two_nexthops_on_r1(topology):
    out = exec_in_check("r1", f"ip route show {topology.ecmp_dest}")
    allure.attach(out, name="ip route show", attachment_type=allure.attachment_type.TEXT)
    for nh in topology.ecmp_nexthops:
        assert nh in out, (
            f"Ожидаемый nexthop {nh} не найден в маршруте к {topology.ecmp_dest}:\n{out}"
        )
    assert out.count("nexthop") >= 2, f"Ожидалось >=2 nexthop, получено:\n{out}"

@allure.story("Проверка сетевой связности через ECMP маршруты")
@allure.severity(allure.severity_level.BLOCKER)
@allure.title("H1 пингует H2 через ECMP-маршрут")
def test_h1_can_reach_h2(topology):
    out = exec_in_check("h1", "ping -c 3 -W 2 10.0.2.10")
    allure.attach(out, name="ping output", attachment_type=allure.attachment_type.TEXT)
    assert "0% packet loss" in out, f"H1 не достучался до H2:\n{out}"
