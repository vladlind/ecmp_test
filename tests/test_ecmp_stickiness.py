"""
Сценарий #5: per-flow consistency — каждый Src IP всегда уходит одним и тем же
nexthop'ом.

Pass: для каждого Src IP только один интерфейс (to-r2 или to-r3), на котором он замечен.
"""

import allure
import pytest

from helpers.capture import Capture
from helpers.common import DEFAULT_BPF, ECMP_INTERFACES, H2_IP, attach_pcaps
from helpers.traffic import send_from_h1
from helpers.analyzer import src_ip_to_ifaces


N_PACKETS = 1000


pytestmark = [
    pytest.mark.stickiness,
    allure.epic("ECMP Source-IP hashing"),
    allure.feature("Stickiness"),
]


@allure.story("Каждый Src IP всегда придерживается своего пути")
@allure.severity(allure.severity_level.CRITICAL)
@allure.title(f"{N_PACKETS} пакетов: каждый Src IP всегда на одном nexthop'е")
def test_each_src_ip_sticks_to_one_path(topology, tmp_path):
    with allure.step(f"Захват + отправка {N_PACKETS} ICMP со случайными Src IP"):
        with Capture(
            interfaces=ECMP_INTERFACES, bpf=DEFAULT_BPF, output_dir=tmp_path,
        ) as pcaps:
            sent_srcs = send_from_h1(count=N_PACKETS, strategy="random")

    attach_pcaps(pcaps)

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
        f"Нарушений stickiness: {len(violations)} (из {len(mapping)} уникальных Src IP). "
        f"Каждый Src IP должен всегда уходить одним и тем же nexthop'ом."
    )
    assert len(mapping) >= int(len(set(sent_srcs)) * 0.95), (
        f"В захвате {len(mapping)} уникальных Src IP, отправлено {len(set(sent_srcs))} — "
        f"захватили <95%, возможны потери."
    )
