"""
Scenario #5: per-flow consistency — each Src IP always leaves via the same
nexthop.

Pass: for each Src IP only one interface (to-r2 or to-r3) it is seen on.
"""

import allure
import pytest

from helpers.common import H2_IP, run_test_traffic
from helpers.analyzer import src_ip_to_ifaces


N_PACKETS = 1000


pytestmark = [
    pytest.mark.stickiness,
    allure.epic("ECMP Source-IP hashing"),
    allure.feature("Stickiness"),
]


@allure.story("Each Src IP always sticks to its own path")
@allure.severity(allure.severity_level.CRITICAL)
@allure.title(f"{N_PACKETS} packets: each Src IP always on one nexthop")
def test_each_src_ip_sticks_to_one_path(topology, tmp_path):
    pcaps, sent_srcs = run_test_traffic(
        output_dir=tmp_path, count=N_PACKETS, strategy="random",
    )

    mapping = src_ip_to_ifaces(pcaps, dst_ip=H2_IP)
    violations = {src: sorted(ifaces) for src, ifaces in mapping.items() if len(ifaces) > 1}

    summary = (
        f"sent unique srcs : {len(set(sent_srcs))}\n"
        f"seen unique srcs : {len(mapping)}\n"
        f"violations       : {len(violations)}"
    )
    allure.attach(summary, name="stickiness summary", attachment_type=allure.attachment_type.TEXT)

    if violations:
        details = "\n".join(f"  {src}: {ifs}" for src, ifs in list(violations.items())[:20])
        allure.attach(details, name="violations (first 20)", attachment_type=allure.attachment_type.TEXT)

    assert not violations, (
        f"Stickiness violations: {len(violations)} (out of {len(mapping)} unique Src IPs). "
        f"Each Src IP must always leave via the same nexthop."
    )
    assert len(mapping) >= int(len(set(sent_srcs)) * 0.95), (
        f"Captured {len(mapping)} unique Src IPs, sent {len(set(sent_srcs))} — "
        f"captured <95%, possible packet loss."
    )
