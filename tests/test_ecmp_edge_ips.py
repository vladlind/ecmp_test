"""
Scenario #6: Edge IP values — the boundary addresses of the 10.99.0.0/16 range.

We send ICMP from the boundary Src IPs of the subnet usually used by the
distribution tests: 10.99.0.0 (network address) and 10.99.255.255 (broadcast
address).
Pass: both Src IPs are captured, and each of them leaves via a single interface.
"""

import allure
import pytest

from helpers.common import H2_IP, run_test_traffic
from helpers.analyzer import src_ip_to_ifaces


N_PACKETS = 100
EDGE_IPS = ("10.99.0.0", "10.99.255.255")


pytestmark = [
    pytest.mark.stickiness,
    allure.epic("ECMP Source-IP hashing"),
    allure.feature("Edge IPs"),
]


@allure.story("Boundary Src IPs are distributed across interfaces the same way as other IPs")
@allure.severity(allure.severity_level.NORMAL)
@allure.title("Edge Src IPs (10.99.0.0 and 10.99.255.255): no drops and via the same interface")
def test_edge_src_ips_are_handled_consistently(topology, tmp_path):
    pcaps, _ = run_test_traffic(
        output_dir=tmp_path, count=N_PACKETS, strategy="edges",
    )

    mapping = src_ip_to_ifaces(pcaps, dst_ip=H2_IP)

    summary = "\n".join(
        f"  {src}: {sorted(mapping.get(src, set())) or '— not captured —'}"
        for src in EDGE_IPS
    )
    allure.attach(
        f"edge Src IP → ifaces:\n{summary}",
        name="edge ip routing",
        attachment_type=allure.attachment_type.TEXT,
    )

    missing = [src for src in EDGE_IPS if src not in mapping]
    assert not missing, (
        f"Edge Src IPs did not reach R1's ECMP interfaces: {missing}. "
    )

    multi_path = {src: sorted(mapping[src]) for src in EDGE_IPS if len(mapping[src]) > 1}
    assert not multi_path, (
        f"Edge Src IPs were spread across multiple nexthops: {multi_path}. "
        f"Stickiness must hold even at the boundary values of the range."
    )
