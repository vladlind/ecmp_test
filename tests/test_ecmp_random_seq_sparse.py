"""
Scenario #4: different Src IP selection methods (random, sequential, sparse)
yield a balanced distribution.

Sequential — adjacent addresses.
Sparse — evenly spread addresses across the whole address pool.
Random — pseudo-random sampling.

Pass: the same criteria as in test_ecmp_distribution, for each strategy.
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
@allure.story("Random and sequential Src IPs are distributed across interfaces in a balanced way")
@allure.severity(allure.severity_level.NORMAL)
@allure.title("Src IP strategy={strategy}: distribution is balanced")
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
