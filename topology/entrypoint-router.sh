#!/bin/bash
# Entrypoint для роутеров R1-R4.
#
# Переменные окружения из compose:
#   ROUTER_NAME     — "r1".."r4"
#   ROUTER_ID       — IP для loopback, напр. "1.1.1.1"
#   IFACE_MAP       — JSON вида: {"10.0.12.1":"to-r2","10.0.13.1":"to-r3"}
#                     (ключ — IP на интерфейсе, значение — желаемое имя)

set -e

echo "[router:${ROUTER_NAME:-?}] starting entrypoint"

# Парсим IFACE_MAP (JSON) -> массив ожидаемых IP.
readarray -t EXPECTED_IPS < <(echo "$IFACE_MAP" | jq -r 'keys[]')

echo "[router:${ROUTER_NAME}] waiting for IPs: ${EXPECTED_IPS[*]}"

# Переименовываем интерфейсы согласно IFACE_MAP.
for expected_ip in "${EXPECTED_IPS[@]}"; do
    new_name=$(echo "$IFACE_MAP" | jq -r --arg ip "$expected_ip" '.[$ip]')
    # Находим текущее имя интерфейса по IP.
    cur_name=$(ip -o -4 addr show | awk -v ip="$expected_ip" '$4 ~ ("^"ip"/") {print $2; exit}')
    if [ -z "$cur_name" ]; then
        echo "[router:${ROUTER_NAME}] WARN: no iface with IP $expected_ip"
        continue
    fi
    if [ "$cur_name" = "$new_name" ]; then
        continue
    fi
    ip link set "$cur_name" down
    ip link set "$cur_name" name "$new_name"
    ip link set "$new_name" up
    echo "[router:${ROUTER_NAME}] renamed $cur_name -> $new_name (IP $expected_ip)"
done

# Loopback с router-id.
if [ -n "$ROUTER_ID" ]; then
    ip addr add "${ROUTER_ID}/32" dev lo 2>/dev/null || true
    echo "[router:${ROUTER_NAME}] loopback router-id: $ROUTER_ID"
fi

# Удаляем навязанный default route
while ip route show default | grep -q .; do
    ip route del default || break
done

echo "[router:${ROUTER_NAME}] interfaces:"
ip -4 addr show | grep -E "^[0-9]+:|inet " | grep -v "127.0.0.1"
echo "[router:${ROUTER_NAME}] routes:"
ip route show

# Запускаем FRR (конфиг подмонтирован в /etc/frr/frr.conf).
/usr/lib/frr/frrinit.sh start
echo "[router:${ROUTER_NAME}] FRR started"

echo "[router:${ROUTER_NAME}] entrypoint done, sleeping"
exec tail -f /dev/null
