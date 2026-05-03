"""
Сценарий #3: 1000 уникальных Src IP — оба пути загружены сбалансированно.

Это headline-проверка ECMP: есть два равноценных пути и hash должен раскидывать
входной поток примерно поровну.

Pass: |доля_пути − 0.5| < 0.1 (т.е. на каждом интерфейсе 40..60%).
"""

import allure
import pytest

from helpers.capture import Capture
from helpers.common import DEFAULT_BPF, ECMP_INTERFACES, H2_IP, attach_pcaps
from helpers.traffic import send_from_h1
from helpers.analyzer import balance_ratio, total_per_iface


N_PACKETS = 1000
BALANCE_TOLERANCE = 0.1  # |p - 0.5| < 0.1 - отклонение баланса в пределах 10% в обе стороны


pytestmark = [
    pytest.mark.distribution,
    allure.epic("ECMP Source-IP hashing"),
    allure.feature("Distribution"),
]


@allure.story("Множество src IP балансирует между двумя маршрутами")
@allure.severity(allure.severity_level.CRITICAL)
@allure.title(f"{N_PACKETS} случайных Src IP → балансировка |p−0.5| < {BALANCE_TOLERANCE}")
def test_many_src_ips_distribute_evenly(topology, tmp_path):
    with allure.step(f"Захват на R1 + отправка {N_PACKETS} ICMP с random Src IP"):
        with Capture(
            interfaces=ECMP_INTERFACES, bpf=DEFAULT_BPF, output_dir=tmp_path,
        ) as pcaps:
            send_from_h1(count=N_PACKETS, strategy="random")

    attach_pcaps(pcaps)

    totals = total_per_iface(pcaps, dst_ip=H2_IP)
    ratios = balance_ratio(pcaps, dst_ip=H2_IP)

    summary = (
        f"packets per iface: {totals}\n"
        f"balance ratios:    { {k: round(v, 4) for k,v in ratios.items()} }"
    )
    allure.attach(summary, name="distribution summary", attachment_type=allure.attachment_type.TEXT)

    captured = sum(totals.values())
    assert captured >= int(N_PACKETS * 0.95), (
        f"Захвачено только {captured}/{N_PACKETS} (<95%) — потери или баг захвата:\n{totals}"
    )

    for iface, p in ratios.items():
        assert abs(p - 0.5) < BALANCE_TOLERANCE, (
            f"Дисбаланс на {iface}: доля {p:.3f} (ожидалось 0.5 ± {BALANCE_TOLERANCE}).\n"
            f"Полные счётчики: {totals}"
        )
