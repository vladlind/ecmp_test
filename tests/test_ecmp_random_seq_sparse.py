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

from helpers.common import (
    H2_IP,
    assert_balanced,
    assert_no_capture_loss,
    attach_distribution_summary,
    run_test_traffic,
)
from helpers.analyzer import balance_ratio, total_per_iface


N_PACKETS = 1000


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
    pcaps, _ = run_test_traffic(
        output_dir=tmp_path, count=N_PACKETS, strategy=strategy,
        pcap_suffix=f"-{strategy}",
    )

    totals = total_per_iface(pcaps, dst_ip=H2_IP)
    ratios = balance_ratio(pcaps, dst_ip=H2_IP)

    attach_distribution_summary(
        totals, ratios, name=f"distribution summary ({strategy})", strategy=strategy,
    )
    assert_no_capture_loss(totals, N_PACKETS, context=strategy)
    assert_balanced(ratios, totals, context=strategy)
