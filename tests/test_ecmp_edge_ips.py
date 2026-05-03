"""
Сценарий #6: Edge IP values — крайние адреса диапазона 10.99.0.0/16.

Шлём ICMP с граничных Src IP подсети, которую обычно используют distribution-
тесты: 10.99.0.0 (network address) и 10.99.255.255 (broadcast address).
Pass: оба Src IP захвачены, и каждый из них уходит через один интерфейс.
"""

import allure
import pytest

from helpers.capture import Capture
from helpers.common import DEFAULT_BPF, ECMP_INTERFACES, H2_IP, attach_pcaps
from helpers.traffic import send_from_h1
from helpers.analyzer import src_ip_to_ifaces


N_PACKETS = 100
EDGE_IPS = ("10.99.0.0", "10.99.255.255")


pytestmark = [
    pytest.mark.stickiness,
    allure.epic("ECMP Source-IP hashing"),
    allure.feature("Edge IPs"),
]


@allure.story("Пограничные Src IPs распределяются по интерфейсам так же как и остальные IP")
@allure.severity(allure.severity_level.NORMAL)
@allure.title("Edge Src IPs (10.99.0.0 и 10.99.255.255): без дропов и через один и тот же интерфейс")
def test_edge_src_ips_are_handled_consistently(topology, tmp_path):
    with allure.step(f"Захват на R1 + отправка {N_PACKETS} ICMP с чередующихся edge Src IP"):
        with Capture(
            interfaces=ECMP_INTERFACES, bpf=DEFAULT_BPF, output_dir=tmp_path,
        ) as pcaps:
            send_from_h1(count=N_PACKETS, strategy="edges")

    attach_pcaps(pcaps)

    mapping = src_ip_to_ifaces(pcaps, dst_ip=H2_IP)

    summary = "\n".join(
        f"  {src}: {sorted(mapping.get(src, set())) or '— не захвачен —'}"
        for src in EDGE_IPS
    )
    allure.attach(
        f"edge Src IP → ifaces:\n{summary}",
        name="edge ip routing",
        attachment_type=allure.attachment_type.TEXT,
    )

    missing = [src for src in EDGE_IPS if src not in mapping]
    assert not missing, (
        f"Edge Src IP не дошли до R1 ECMP-интерфейсов: {missing}. "
    )

    multi_path = {src: sorted(mapping[src]) for src in EDGE_IPS if len(mapping[src]) > 1}
    assert not multi_path, (
        f"Edge Src IP размазались по нескольким nexthop'ам: {multi_path}. "
        f"Stickiness должен держаться и на крайних значениях диапазона."
    )
