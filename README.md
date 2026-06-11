# ECMP Hash Test (Source IP)

Automated verification of ECMP (Equal-Cost Multi-Path) with a **Source IP**
hash algorithm on an FRR + OSPF testbed running in Docker.

The testbed comes up with a single command; pytest runs 7 scenarios and the
results are published to an Allure report with attached pcaps.

## Running the framework and the tests

```bash
./run.sh test    # brings everything up, runs all tests, writes results to allure-results.
```

This command:
1. Brings up the testbed of 6 network containers + the runner.
2. Applies the Docker bridge fixes required for OSPF multicast to pass.
3. Waits for OSPF to converge (≤60 s).
4. Runs pytest inside the runner; results in Allure format land in
   `reports/allure-results/`.


## Topology

```
                    ┌──── R2 ────┐
                    │            │
   [H1] ────── R1 ──┤            ├── R4 ──── [H2]
                    │            │
                    └──── R3 ────┘
```

- **R1** — the border router on the H1 side, **where the ECMP decision is made**.
  `maximum-paths 2` in FRR + `fib_multipath_hash_policy=0` in Linux (= L3 hash
  over Src+Dst IP). With a fixed Dst IP (always H2 = 10.0.2.10) the hash is
  effectively taken over the Source IP.
- **R2, R3** — two equal-cost intermediate paths (same OSPF cost).
- **R4** — the border router on the H2 side.

All links are point-to-point (`/29` in Docker IPAM, effectively p2p), all
interfaces are in OSPF area 0. Each link = a separate bridge.

### Addressing

| Link / interface | Network      | IP addresses                        |
|------------------|--------------|-------------------------------------|
| H1 ↔ R1          | 10.0.1.0/24  | H1=10.0.1.10, R1=10.0.1.1           |
| R1 ↔ R2          | 10.0.12.0/29 | R1=10.0.12.1, R2=10.0.12.2          |
| R1 ↔ R3          | 10.0.13.0/29 | R1=10.0.13.1, R3=10.0.13.2          |
| R2 ↔ R4          | 10.0.24.0/29 | R2=10.0.24.1, R4=10.0.24.2          |
| R3 ↔ R4          | 10.0.34.0/29 | R3=10.0.34.1, R4=10.0.34.2          |
| R4 ↔ H2          | 10.0.2.0/24  | R4=10.0.2.1, H2=10.0.2.10           |
| Loopbacks        | /32          | R1..R4 = 1.1.1.1 .. 4.4.4.4         |

H1 additionally has a secondary range **10.99.0.0/16** on its uplink — the
tests pick the "set of sources" from it to verify hash-based distribution.

## Requirements

- Ubuntu 24.04. On WSL2 — Docker Desktop with WSL integration enabled for the
  target distro.
- Docker Engine ≥ 20.10 + Docker Compose v2.
- Kernel ≥ 5.15 (for `fib_multipath_hash_policy`).
- (optional, for viewing the report) — Allure (on the host or via Docker).

No host-side Python/pytest is required — everything runs inside the runner
container.

## Test scenarios

Every test automatically verifies that the testbed is ready (the `topology`
fixture waits for OSPF convergence and for the ECMP route to be present); if
the testbed is not up, the test fails immediately with a hint to run
`./run.sh`.

| # | File                            | What we check                                     | Pass criterion                      |
|---|---------------------------------|---------------------------------------------------|-------------------------------------|
| 1 | `test_ecmp_smoke.py`            | ECMP route to 10.0.2.0/24 on R1; H1 pings H2      | ≥2 nexthops in the FIB; ping 0% loss       |
| 2 | `test_ecmp_same_src.py`         | From a single Src IP all traffic takes one path   | ≥99% of packets on one interface    |
| 3 | `test_ecmp_distribution.py`     | 1000 random Src IPs → balancing; parametrized over `{ICMP, UDP, TCP}` — verifying that the L3 hash (Src+Dst IP) balances different L4 protocols equally | \|p − 0.5\| < 0.1 on each path for each of the three protocols |
| 4 | `test_ecmp_random_seq_sparse.py`       | Src IP selection strategies: `random` (pseudo-random), `sequential` (adjacent) and `sparse` (evenly spread) — all three must balance | \|p − 0.5\| < 0.1 on each path for each of the three strategies |
| 5 | `test_ecmp_stickiness.py`       | A single Src IP always leaves via the same nexthop | 0 per-flow consistency violations   |
| 6 | `test_ecmp_edge_ips.py`         | Edge Src IPs of the 10.99.0.0/16 range (network/broadcast) are handled by the hash without drops | both IPs captured and each goes through one interface |
| 7 | `test_ecmp_link_failure.py`     | After `to-r2 down` on R1 traffic shifts entirely through R3 with no loss; after `to-r2 up` the second nexthop returns and traffic balances between R2 and R3 | 1 nexthop via R3 remains in the FIB; \|p − 0.5\| < 0.1 on each path after the second nexthop is restored |

Each test attaches to the Allure report the pcaps from the R1 interfaces
(`to-r2`, `to-r3`) and a text summary of counters and ratios.


## Repository structure

```
ecmp-test/
├── README.md                      ← documentation
├── run.sh                         ← entry point ("one button")
├── docker-compose.yml             ← 6 network containers + runner + init-bridges
├── Dockerfile.host                ← H1, H2 (debian + scapy + tcpdump)
├── Dockerfile.frr                 ← R1..R4 (debian + FRR + tcpdump)
├── Dockerfile.runner              ← runner (python3 + pytest + allure + scapy)
├── topology/
│   ├── entrypoint-host.sh         ← iface rename, default route, secondary IP
│   ├── entrypoint-router.sh       ← iface rename, FRR start, sysctls
│   └── frr-r{1..4}.conf           ← FRR configs (OSPF area 0, point-to-point)
├── tests/
│   ├── pytest.ini                 ← markers + verbose
│   ├── conftest.py                ← topology fixture
│   ├── test_ecmp_*.py             ← 7 scenarios (13 tests)
│   └── helpers/
│       ├── h1_send.py             ← scapy generator (runs INSIDE h1)
│       ├── traffic.py             ← runner-side wrapper over h1_send
│       ├── capture.py             ← Capture (tcpdump streaming into pcap)
│       ├── analyzer.py            ← pcap parsing (counters, balances)
│       └── common.py              ← shared constants + exec_in helpers + attach_pcaps
└── reports/                       ← allure-results / allure-report (gitignored)
```

## Key technical decisions

### Per-link bridges, not a shared broadcast segment
Each L2 link = a separate Docker bridge (`br-h1r1`, `br-r1r2`, ...). On p2p
segments tcpdump on `to-r2` captures **only** the traffic through R2.

### The `init-bridges` service in compose
By default Docker sets `multicast_snooping=1` on each bridge, and
`bridge-nf-call-iptables=1` globally on the host. Together they drop OSPF
Hello (224.0.0.5) before it even leaves the bridge.

Solution: a privileged `init-bridges` service with `network_mode: host` and
`condition: service_completed_successfully`. All other services depend on it —
this guarantees multicast works by the time the routers start.

### `rp_filter=0` on the routers
The tests send packets with arbitrary Src IPs from `10.99.0.0/16` (H1's
secondary range). R1 has no return route to that network, and the strict RPF
check (default = 1) would drop such packets.

### Runner
The runner issues the traffic-sending and capture commands through the mounted
`/var/run/docker.sock`. This simplifies debugging: any test step can be
reproduced by hand with a single `docker exec` command.

## Troubleshooting

**`./run.sh` fails with "OSPF did not converge within 60s".**
Bring the testbed up manually and check:
- `docker exec r1 vtysh -c "show ip ospf neighbor"` — there should be two
  `Full/-` neighbors.
- On the host: `docker run --rm --privileged --net=host alpine cat /proc/sys/net/bridge/bridge-nf-call-iptables`
  — should be 0. If it is 1, then `init-bridges` didn't run; check
  `docker logs ecmp-init-bridges`.
- Logs of the starting containers: `docker logs r1`, `docker logs r2`, …

**If the Allure CLI is not installed.**
The run results are saved to `reports/allure-results/`. To produce the HTML
report, install allure or do it via Docker:
```bash
docker run --rm -v $(pwd)/reports:/reports frankescobar/allure-docker-service:latest \
  allure generate /reports/allure-results -o /reports/allure-report \
  --clean --single-file
```

**If docker won't start on WSL2.**
Enable WSL integration in Docker Desktop → Settings → Resources →
WSL Integration for the target distro and run `wsl --shutdown` from PowerShell.
