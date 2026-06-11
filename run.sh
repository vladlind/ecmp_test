#!/usr/bin/env bash
# Deploy the test environment and verify the ECMP routes are present after OSPF converges.
# Usage:
#   ./run.sh           — see line 2 above
#   ./run.sh test      — see line 2 above + run the tests and generate reports

set -euo pipefail

cd "$(dirname "$0")"

echo "[run.sh] docker compose up -d --build"
docker compose up -d

echo "[run.sh] waiting for OSPF convergence on R1 (ECMP route to 10.0.2.0/24)..."
deadline=$(( $(date +%s) + 60 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  nh=$(docker exec r1 ip route show 10.0.2.0/24 2>/dev/null | grep -c "^\s*nexthop" || true)
  if [ "${nh:-0}" -ge 2 ]; then
    echo "[run.sh] OSPF converged — R1 has $nh ECMP nexthops:"
    docker exec r1 ip route show 10.0.2.0/24
    break
  fi
  sleep 1
done

if [ "${nh:-0}" -lt 2 ]; then
  echo "[run.sh] FATAL: OSPF did not converge within 60s"
  echo "--- R1 OSPF neighbors ---"
  docker exec r1 vtysh -c "show ip ospf neighbor" || true
  echo "--- R1 route to 10.0.2.0/24 ---"
  docker exec r1 ip route show 10.0.2.0/24 || true
  exit 1
fi

if [ "${1:-}" = "test" ]; then
  echo "[run.sh] running pytest in runner container"
  rc=0
  docker exec runner pytest /tests --alluredir=/reports/allure-results --clean-alluredir || rc=$?
  echo "[run.sh] tearing down stack (docker compose down -v)"
  docker compose down -v
  exit $rc
fi
