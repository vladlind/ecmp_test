# ECMP Hash Test (Source IP)

Автоматизированная проверка работы ECMP (Equal-Cost Multi-Path) с
hash-алгоритмом по **Source IP** на стенде из FRR + OSPF в Docker.

Стенд поднимается одной командой; pytest гоняет 7 сценариев,
результаты публикуются в Allure-отчёт с прикреплёнными pcap'ами.

## Запуск фреймворка и тестов

```bash
./run.sh test    # поднимает всё, прогоняет все тесты и кладёт результаты в allure-results.
```

Эта команда:
1. Поднимает стенд из 6 сетевых контейнеров + runner.
2. Применяет фиксы Docker bridge, нужные для прохождения OSPF multicast
3. Ждёт сходимости OSPF (≤60 с).
4. Запускает pytest внутри runner'а; результаты в Allure-формате
   ложатся в `reports/allure-results/`.


## Топология

```
                    ┌──── R2 ────┐
                    │            │
   [H1] ────── R1 ──┤            ├── R4 ──── [H2]
                    │            │
                    └──── R3 ────┘
```

- **R1** — пограничный роутер со стороны H1, **здесь принимается ECMP-решение**.
  `maximum-paths 2` в FRR + `fib_multipath_hash_policy=0` в Linux (= L3 hash
  по Src+Dst IP). С фиксированным Dst IP (всегда H2 = 10.0.2.10) hash
  фактически берётся по Source IP.
- **R2, R3** — два равноценных промежуточных пути (одинаковая OSPF cost).
- **R4** — пограничный роутер со стороны H2.

Все линки point-to-point (`/29` в Docker IPAM, фактически p2p), все
интерфейсы в OSPF area 0. Каждый линк = отдельный bridge.

### Адресация

| Линк / интерфейс | Сеть         | IP-адреса                           |
|------------------|--------------|-------------------------------------|
| H1 ↔ R1          | 10.0.1.0/24  | H1=10.0.1.10, R1=10.0.1.1           |
| R1 ↔ R2          | 10.0.12.0/29 | R1=10.0.12.1, R2=10.0.12.2          |
| R1 ↔ R3          | 10.0.13.0/29 | R1=10.0.13.1, R3=10.0.13.2          |
| R2 ↔ R4          | 10.0.24.0/29 | R2=10.0.24.1, R4=10.0.24.2          |
| R3 ↔ R4          | 10.0.34.0/29 | R3=10.0.34.1, R4=10.0.34.2          |
| R4 ↔ H2          | 10.0.2.0/24  | R4=10.0.2.1, H2=10.0.2.10           |
| Loopbacks        | /32          | R1..R4 = 1.1.1.1 .. 4.4.4.4         |

H1 дополнительно имеет secondary range **10.99.0.0/16** на uplink — из него
тесты выбирают «множество источников» для проверки распределения по hash'у.

## Требования

- Ubuntu-24.04. Если на WSL2 — то Docker Desktop с включённой WSL-интеграцией
  для целевого дистрибутива.
- Docker Engine ≥ 20.10 + Docker Compose v2.
- Ядро ≥ 5.15 (для `fib_multipath_hash_policy`).
- (опционально, для просмотра отчёта) - Allure (на хосте или через Docker)

Сторонние Python/pytest на хосте не нужны — всё едет внутрь runner-контейнера.

## Сценарии тестов

Все тесты автоматически верифицируют, что стенд готов (фикстура `topology`
ждёт сходимости OSPF и наличия ECMP-маршрута); если стенд не поднят — тест
сразу фейлится с подсказкой запустить `./run.sh`.

| # | Файл                            | Что проверяем                                     | Критерий pass                       |
|---|---------------------------------|---------------------------------------------------|-------------------------------------|
| 1 | `test_ecmp_smoke.py`            | ECMP-маршрут к 10.0.2.0/24 на R1; H1 пингует H2   | в FIB ≥2 nexthop'а; ping 0% loss          |
| 2 | `test_ecmp_same_src.py`         | С одного Src IP весь трафик одним путем     | ≥99% пакетов на одном интерфейсе    |
| 3 | `test_ecmp_distribution.py`     | 1000 случайных Src IP → балансировка; параметризован по `{ICMP, UDP, TCP}` — проверяем, что L3-hash (Src+Dst IP) одинаково балансирует разные L4-протоколы | \|p − 0.5\| < 0.1 на каждом из путей для каждого из трёх протоколов |
| 4 | `test_ecmp_random_seq.py`       | Random и sequential Src IP оба балансируются      | тот же, что #3, для обеих стратегий   |
| 5 | `test_ecmp_stickiness.py`       | Один Src IP всегда уходит одним nexthop'ом        | 0 нарушений per-flow consistency    |
| 6 | `test_ecmp_edge_ips.py`         | Граничные Src IP диапазона 10.99.0.0/16 (network/broadcast) обрабатываются hash'ом без дропов | оба IP захвачены и каждый идет через один интерфейс |
| 7 | `test_ecmp_link_failure.py`     | После `to-r2 down` на R1 трафик уходит целиком через R3, без потерь; после `to-r2 up` второй nexthop возвращается и трафик балансируется между R2 и R3   | в FIB остаётся 1 nexthop через R3; \|p − 0.5\| < 0.1 на каждом из путей |

Каждый тест прикрепляет к Allure-репорту pcap'ы с интерфейсов R1
(`to-r2`, `to-r3`) и текстовую сводку счётчиков и долей.


## Структура репозитория

```
ecmp-test/
├── README.md                      ← документация
├── run.sh                         ← точка входа («одной кнопкой»)
├── docker-compose.yml             ← 6 сетевых контейнеров + runner + init-bridges
├── Dockerfile.host                ← H1, H2 (debian + scapy + tcpdump)
├── Dockerfile.frr                 ← R1..R4 (debian + FRR + tcpdump)
├── Dockerfile.runner              ← runner (python3 + pytest + allure + scapy)
├── topology/
│   ├── entrypoint-host.sh         ← переименование iface, default route, secondary IP
│   ├── entrypoint-router.sh       ← переименование iface, FRR start, sysctls
│   └── frr-r{1..4}.conf           ← FRR configs (OSPF area 0, point-to-point)
├── tests/
│   ├── pytest.ini                 ← маркеры + verbose
│   ├── conftest.py                ← фикстура topology
│   ├── test_ecmp_*.py             ← 7 сценариев (12 тестов)
│   └── helpers/
│       ├── h1_send.py             ← scapy-генератор (запускается ВНУТРИ h1)
│       ├── traffic.py             ← runner-side обёртка над h1_send
│       ├── capture.py             ← Capture (tcpdump streaming в pcap)
│       ├── analyzer.py            ← разбор pcap (счётчики, балансы)
│       └── common.py              ← общие константы + exec_in helpers + attach_pcaps
└── reports/                       ← allure-results / allure-report (gitignored)
```

## Ключевые технические решения

### Per-link bridges, не общий broadcast-сегмент
Каждый L2-линк = отдельный Docker bridge (`br-h1r1`, `br-r1r2`, ...). На p2p
сегментах tcpdump на `to-r2` ловит **только** трафик через R2.

### `init-bridges` сервис в compose
Docker по умолчанию ставит на каждом bridge'е `multicast_snooping=1`, и
`bridge-nf-call-iptables=1` — глобально на хосте. Вместе это дропает OSPF
Hello (224.0.0.5) ещё до выхода с моста.

Решение: privileged + `network_mode: host` сервис `init-bridges` с
`condition: service_completed_successfully`. Все остальные сервисы зависят
от него — гарантирует, что multicast будет работать к моменту старта роутеров.

### `rp_filter=0` на роутерах
Тесты шлют пакеты с произвольных Src IP из `10.99.0.0/16` (secondary range
H1). У R1 нет обратного маршрута к этой сети, и strict RPF check
(default = 1) такие пакеты дропает.

### Runner
Runner запускает команды для отправки и захвата трафика через смонтированный
`/var/run/docker.sock`. Это упрощает отладку: любой
шаг теста воспроизводится руками одной `docker exec`-командой.

## Troubleshooting

**`./run.sh` падает с «OSPF did not converge within 60s».**
Надо запустить стенд вручную и проверить:
- `docker exec r1 vtysh -c "show ip ospf neighbor"` — должно быть два
  `Full/-` соседа.
- На хосте: `docker run --rm --privileged --net=host alpine cat /proc/sys/net/bridge/bridge-nf-call-iptables`
  — должен быть 0. Если 1 — значит `init-bridges` не отработал; смотрите
  `docker logs ecmp-init-bridges`.
- Логи стартующих контейнеров: `docker logs r1`, `docker logs r2`, …

**Если Allure CLI не установлен.**
Результаты прогона сохраняются в `reports/allure-results/`. Для создания
HTML с отчетом — нужно поставить allure или сделать это через Docker:
```bash
docker run --rm -v $(pwd)/reports:/reports frankescobar/allure-docker-service:latest \
  allure generate /reports/allure-results -o /reports/allure-report \
  --clean --single-file
```

**Если на WSL2 docker не запускается**
Нужно включить WSL-интеграцию в Docker Desktop → Settings → Resources →
WSL Integration для целевого distro и сделать `wsl --shutdown` из PowerShell.


