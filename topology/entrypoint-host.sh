#!/bin/bash
# Entrypoint for the H1/H2 hosts.
#
# Environment variables expected from compose:
#   HOSTNAME_ROLE  — "h1" or "h2" (for diagnostic output)
#   GATEWAY        — IP of the border router (R1 for H1, R4 for H2)
#   SECONDARY_CIDR — (H1 only) a range like 10.99.0.0/16 for the secondary IP

set -e

echo "[host:${HOSTNAME_ROLE:-?}] starting entrypoint"

# Wait until an interface with a non-loopback IP appears (max ~5 sec).
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

# Rename to uplink for a stable, predictable interface name.
ip link set "$IFACE" down
ip link set "$IFACE" name uplink
ip link set uplink up
IFACE=uplink

# Remove any default routes Docker may have added.
while ip route show default | grep -q .; do
    ip route del default || break
done

# Set our own default route via the specified gateway.
if [ -n "$GATEWAY" ]; then
    ip route add default via "$GATEWAY" dev "$IFACE"
    echo "[host:${HOSTNAME_ROLE}] default route via $GATEWAY"
else
    echo "[host:${HOSTNAME_ROLE}] WARNING: GATEWAY not set, no default route"
fi

# Secondary IP range for H1 — needed for the many-Source-IP scenario.
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
