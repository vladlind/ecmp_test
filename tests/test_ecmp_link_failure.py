"""
Сценарий #7: Link failure — переход на оставшийся путь.

Гасим to-r2 на R1 (`ip link set to-r2 down`), ждём, пока OSPF удалит nexthop
через R2, потом шлём трафик с разными Src IP. Проверяем:
  (а) ECMP-маршрут на R1 теперь имеет один nexthop (через R3);
  (б) ни один пакет не потерян после сходимости (>=99% из отправленных
      пойманы на R1);
  (в) 100% пойманного трафика прошло через to-r3.

В teardown поднимаем интерфейс обратно и ждём восстановления ECMP, чтобы
последующие тесты сессии работали на полноценной топологии.
"""

from __future__ import annotations

import time

import allure
import pytest

from helpers.capture import Capture
from helpers.common import (
    DEFAULT_BPF,
    ECMP_DEST_NET,
    H2_IP,
    attach_pcaps,
    exec_in,
    exec_in_check,
)
from helpers.traffic import send_from_h1
from helpers.analyzer import balance_ratio, total_per_iface


N_PACKETS = 500
RECONVERGE_TIMEOUT_S = 60    # ждем долго, так как приходится рестартовать frr - см.ниже коммент
DOWN_NEXTHOP = "10.0.12.2"   # через R2 — должен исчезнуть
ALIVE_NEXTHOP = "10.0.13.2"  # через R3 — должен остаться
BALANCE_TOLERANCE = 0.1  # |p - 0.5| < 0.1 - отклонение баланса в пределах 10% в обе стороны

pytestmark = [
    pytest.mark.distribution,
    allure.epic("ECMP Source-IP hashing"),
    allure.feature("Link failure"),
]

"""
Обертка над boolean функцией c таймаутом - выполнять функцию в переделах таймаута, пока не вернет true
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


@pytest.fixture
def to_r2_down(topology):
    """
    Кладет to-r2 на R1, ждёт OSPF-сходимости на единственный nexthop через R3.
    На teardown поднимает интерфейс обратно и дожидается, пока ECMP-маршрут
    с >=2 nexthop'ами вернётся
    """
    exec_in_check("r1", "ip link set to-r2 down")
    try:
        if not _wait_until(_route_via_r3_only, RECONVERGE_TIMEOUT_S):
            out = exec_in("r1", f"ip route show {ECMP_DEST_NET}").stdout
            pytest.fail(
                f"OSPF не выкинул nexthop через R2 за {RECONVERGE_TIMEOUT_S}s. "
                f"Текущий маршрут на R1:\n{out}",
                pytrace=False,
            )
        yield
    finally:
        if not _route_has_ecmp():
            out = exec_in("r1", f"ip route show {ECMP_DEST_NET}").stdout
            pytest.fail(
                f"После поднятия to-r2 ECMP не восстановился за "
                f"{RECONVERGE_TIMEOUT_S}s. Маршрут на R1:\n{out}",
                pytrace=False,
            )


@allure.story("После отключения одного из линков трафик идет по оставшемуся пути, после восстановления - балансируется")
@allure.severity(allure.severity_level.CRITICAL)
@allure.title("to-r2 down: маршрут удаляется на R3, весь трафик идёт через R3, без потерь, после восстановления to-r2 - балансируется по двум nexthop'ам")
def test_link_failure_falls_back_to_remaining_path(to_r2_down, tmp_path):
    route_after_down = exec_in("r1", f"ip route show {ECMP_DEST_NET}").stdout
    allure.attach(
        route_after_down,
        name="r1 route after to-r2 down",
        attachment_type=allure.attachment_type.TEXT,
    )
    assert ALIVE_NEXTHOP in route_after_down and DOWN_NEXTHOP not in route_after_down, (
        f"Ожидался единственный nexthop через {ALIVE_NEXTHOP}, факт:\n{route_after_down}"
    )
    assert route_after_down.count("nexthop") <= 1, (
        f"Маршрут всё ещё multipath после падения to-r2:\n{route_after_down}"
    )

    with allure.step(f"Захват на to-r3 + отправка {N_PACKETS} ICMP со случайными Src IP"):
        with Capture(
            interfaces=["to-r3"], bpf=DEFAULT_BPF, output_dir=tmp_path,
        ) as pcaps:
            sent = send_from_h1(count=N_PACKETS, strategy="random")

    attach_pcaps(pcaps)

    totals = total_per_iface(pcaps, dst_ip=H2_IP)
    allure.attach(
        f"sent: {len(sent)}\ncaptured per iface: {totals}",
        name="link-failure summary",
        attachment_type=allure.attachment_type.TEXT,
    )

    captured = sum(totals.values())
    assert captured >= int(N_PACKETS * 0.99), (
        f"После сходимости поймано {captured}/{N_PACKETS} пакетов на to-r3 — "
        f"есть потери, хотя живой путь существует."
    )
    assert totals.get("to-r3", 0) == captured, (
        f"Не весь захваченный трафик прошёл через to-r3: {totals}"
    )


    exec_in("r1", "ip link set to-r2 up")
    """
    Рестарт frr вынужденный - после включения линка zebra почему-то не принимает
    восстановленный мульти-хоп маршрут от ospf. 
    Похоже на описание в баг-репорте - https://github.com/FRRouting/frr/issues/15505
    """
    exec_in("r1", "/usr/lib/frr/frrinit.sh restart")

    if not _wait_until(_route_via_r2_and_r3, RECONVERGE_TIMEOUT_S):
        routes_after_up = exec_in("r1", f"ip route show {ECMP_DEST_NET}").stdout
        ospf_rib_after_up = exec_in("r1", f"show ip route ospf {ECMP_DEST_NET}", "vtysh").stdout
        pytest.fail(
            f"nexthop через R2 не вернулся за {RECONVERGE_TIMEOUT_S}s. "
            f"Текущий маршрут на R1:\n{routes_after_up}",
            f"OSPF RIB на R1:\n{ospf_rib_after_up}",
            pytrace=False,
        )

    routes_after_up = exec_in("r1", f"ip route show {ECMP_DEST_NET}").stdout
    
    allure.attach(
        routes_after_up,
        name="r1 route after to-r2 is up",
        attachment_type=allure.attachment_type.TEXT,
    )

    with allure.step(f"Захват на to-r2 и to-r3 + отправка {N_PACKETS} ICMP со случайными Src IP"):
        with Capture(
            interfaces=["to-r2", "to-r3"], bpf=DEFAULT_BPF, output_dir=tmp_path,
        ) as pcaps_after:
            sent = send_from_h1(count=N_PACKETS, strategy="random")

    attach_pcaps(pcaps_after)

    totals_after = total_per_iface(pcaps_after, dst_ip=H2_IP)

    allure.attach(
        f"sent: {len(sent)}\ncaptured per iface: {totals_after}",
        name="link-recovery summary",
        attachment_type=allure.attachment_type.TEXT,
    )

    captured_after = sum(totals_after.values())
    ratios = balance_ratio(pcaps_after, dst_ip=H2_IP)

    summary = (
        f"packets per iface: {totals_after}\n"
        f"balance ratios:    { {k: round(v, 4) for k,v in ratios.items()} }"
    )

    allure.attach(summary, name="distribution summary after recovery", attachment_type=allure.attachment_type.TEXT)

    for iface, p in ratios.items():
        assert abs(p - 0.5) < BALANCE_TOLERANCE, (
            f"Дисбаланс на {iface}: доля {p:.3f} (ожидалось 0.5 ± {BALANCE_TOLERANCE}).\n"
            f"Полные счётчики: {totals}"
        )
