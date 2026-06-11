"""
Scenario #2 (control/negative): from a single Src IP all traffic takes one path.

Confirms the hash is deterministic: if the input is constant, the output choice
is the same every time. This guards against a false-positive "even" distribution
that could arise, for example, if the hash ignored the Src IP and used something
else.

Pass: >=99% of packets on one of {to-r2, to-r3}.
"""

import allure
import pytest

from helpers.common import H2_IP, assert_no_capture_loss, run_test_traffic
from helpers.analyzer import total_per_iface


N_PACKETS = 200
SAME_PATH_THRESHOLD = 0.99


pytestmark = [
    pytest.mark.distribution,
    allure.epic("ECMP Source-IP hashing"),
    allure.feature("Distribution"),
]


@allure.story("A single Src IP always takes one path")
@allure.severity(allure.severity_level.CRITICAL)
@allure.title("Single Src IP → all traffic via one nexthop (>=99%)")
def test_single_src_ip_pins_to_single_path(topology, tmp_path):
    pcaps, _ = run_test_traffic(
        output_dir=tmp_path, count=N_PACKETS, strategy="single", src="10.0.1.10",
    )

    totals = total_per_iface(pcaps, dst_ip=H2_IP)
    allure.attach(
        f"{totals}", name="packets per iface", attachment_type=allure.attachment_type.TEXT,
    )

    assert_no_capture_loss(totals, N_PACKETS, min_ratio=0.99)

    captured = sum(totals.values())
    max_share = max(totals.values()) / captured
    chosen = max(totals, key=totals.get)
    assert max_share >= SAME_PATH_THRESHOLD, (
        f"Expected >={SAME_PATH_THRESHOLD*100:.0f}% on one interface, "
        f"actual: {totals} (max {max_share*100:.1f}% on {chosen})"
    )
