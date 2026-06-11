"""
Scenario #3: 1000 unique Src IPs — both paths are loaded in a balanced way.

This is the headline ECMP check: there are two equal-cost paths and the hash
must spread the input flow roughly evenly.

Pass: |path_ratio − 0.5| < 0.1 (i.e. 40..60% on each interface).
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

@pytest.mark.parametrize("proto", ["ICMP", "UDP", "TCP"])
@allure.story("Many src IPs balance across the two routes")
@allure.severity(allure.severity_level.CRITICAL)
@allure.title(f"{N_PACKETS} {{proto}} random Src IPs → balanced traffic ratio within 40%..60%")
def test_many_src_ips_distribute_evenly(topology, tmp_path, proto):
    pcaps, _ = run_test_traffic(
        output_dir=tmp_path, count=N_PACKETS, strategy="random", proto=proto,
    )

    totals = total_per_iface(pcaps, dst_ip=H2_IP)
    ratios = balance_ratio(pcaps, dst_ip=H2_IP)

    attach_distribution_summary(totals, ratios, name=f"distribution summary for {proto}")
    assert_no_capture_loss(totals, N_PACKETS)
    assert_balanced(ratios, totals)
