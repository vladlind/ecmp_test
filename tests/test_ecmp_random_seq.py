"""
Сценарий #4: разные способы выбора Src IP (random, sequential, sparse) дают
сбалансированное распределение.

Sequential — соседние адреса.
Sparse — равномерно разреженные адреса по всему пулу адресов.
Random — псевдослучайная выборка.

Pass: те же критерии, что в test_ecmp_distribution для каждой стратегии.
"""

import allure
import pytest

from helpers.capture import Capture
from helpers.common import DEFAULT_BPF, ECMP_INTERFACES, H2_IP, attach_pcaps
from helpers.traffic import send_from_h1
from helpers.analyzer import balance_ratio, total_per_iface


N_PACKETS = 1000
BALANCE_TOLERANCE = 0.1


pytestmark = [
    pytest.mark.distribution,
    allure.epic("ECMP Source-IP hashing"),
    allure.feature("Distribution"),
]


@pytest.mark.parametrize("strategy", ["random", "sequential", "sparse"])
@allure.story("Случайные и последовательные Src IPs распределяются по интерфейсам сбалансировано")
@allure.severity(allure.severity_level.NORMAL)
@allure.title("Стратегия Src IP={strategy}: распределение сбалансировано")
def test_random_and_sequential_both_balance(topology, tmp_path, strategy):
    with allure.step(f"Захват на R1 + отправка {N_PACKETS} ICMP, стратегия={strategy}"):
        with Capture(
            interfaces=ECMP_INTERFACES, bpf=DEFAULT_BPF, output_dir=tmp_path,
        ) as pcaps:
            send_from_h1(count=N_PACKETS, strategy=strategy)

    attach_pcaps(pcaps, suffix=f"-{strategy}")

    totals = total_per_iface(pcaps, dst_ip=H2_IP)
    ratios = balance_ratio(pcaps, dst_ip=H2_IP)
    allure.attach(
        f"strategy={strategy}\npackets per iface: {totals}\nbalance ratios: "
        f"{ {k: round(v, 4) for k,v in ratios.items()} }",
        name=f"distribution summary ({strategy})",
        attachment_type=allure.attachment_type.TEXT,
    )

    captured = sum(totals.values())
    assert captured >= int(N_PACKETS * 0.95), (
        f"Захвачено только {captured}/{N_PACKETS} (стратегия {strategy}):\n{totals}"
    )

    for iface, p in ratios.items():
        assert abs(p - 0.5) < BALANCE_TOLERANCE, (
            f"[{strategy}] Дисбаланс на {iface}: доля {p:.3f} "
            f"(ожидалось 0.5 ± {BALANCE_TOLERANCE}). Полные: {totals}"
        )
