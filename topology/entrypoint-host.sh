#!/bin/bash
# Entrypoint для хостов H1/H2.
#
# Переменные окружения, ожидаемые из compose:
#   HOSTNAME_ROLE  — "h1" или "h2" (для diagnostic-вывода)
#   GATEWAY        — IP пограничного роутера (R1 для H1, R4 для H2)
#   SECONDARY_CIDR — (только для H1) диапазон вида 10.99.0.0/16 для secondary IP

set -e

echo "[host:${HOSTNAME_ROLE:-?}] starting entrypoint"

# Ждём, пока интерфейс с не-loopback IP появится (max ~5 сек).
for i in $(seq 1 50); do
    IFACE=$(ip -o -4 addr show | awk '$2 != "lo" {print $2; exit}')
    [ -n "$IFACE" ] && break
    sleep 0.1
done

if [ -z "$IFACE" ]; then
    echo "[host:${HOSTNAME_ROLE}] FATAL: no non-loopback interface found"
    exit 1
fi

echo "[host:${HOSTNAME_ROLE}] found interface: $IFACE"

# Переименуем в uplink для 
ip link set "$IFACE" down
ip link set "$IFACE" name uplink
ip link set uplink up
IFACE=uplink

# Удаляем все default routes, которые Docker мог навесить.
while ip route show default | grep -q .; do
    ip route del default || break
done

# Ставим свой default через указанный шлюз.
if [ -n "$GATEWAY" ]; then
    ip route add default via "$GATEWAY" dev "$IFACE"
    echo "[host:${HOSTNAME_ROLE}] default route via $GATEWAY"
else
    echo "[host:${HOSTNAME_ROLE}] WARNING: GATEWAY not set, no default route"
fi

# Secondary IP range для H1 — нужен для сценария с множеством Source IP.
if [ -n "$SECONDARY_CIDR" ]; then
    ip addr add "$SECONDARY_CIDR" dev "$IFACE"
    echo "[host:${HOSTNAME_ROLE}] secondary range: $SECONDARY_CIDR"
fi

echo "[host:${HOSTNAME_ROLE}] interface state:"
ip -4 addr show "$IFACE"
echo "[host:${HOSTNAME_ROLE}] routing table:"
ip route show

echo "[host:${HOSTNAME_ROLE}] entrypoint done, sleeping"
exec tail -f /dev/null
