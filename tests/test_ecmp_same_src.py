"""
Сценарий #2 (контроль/негатив): с одного Src IP весь трафик идёт одной дорогой.

Подтверждает детерминизм hash'а: если входной материал постоянный, выходной
выбор тоже один и тот же. Это страховка от ложноположительного «равномерного»
распределения, которое могло бы возникнуть, например, если хеш игнорирует
Src IP и берёт что-то ещё.

Pass: >=99% пакетов на одном из {to-r2, to-r3}.
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


@allure.story("Один Src IP всегда одним путем")
@allure.severity(allure.severity_level.CRITICAL)
@allure.title("Один Src IP → весь трафик одним nexthop'ом (>=99%)")
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
        f"Ожидалось >={SAME_PATH_THRESHOLD*100:.0f}% на одном интерфейсе, "
        f"факт: {totals} (макс. {max_share*100:.1f}% на {chosen})"
    )
