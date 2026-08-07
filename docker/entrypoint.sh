#!/bin/sh
set -eu

if [ "${L2TP_NAT_ENABLED:-true}" = "true" ]; then
  client_subnet="${L2TP_CLIENT_SUBNET:-10.0.0.0/24}"
  outbound_interface="${L2TP_NAT_INTERFACE:-}"
  if [ -z "$outbound_interface" ]; then
    outbound_interface="$(ip -4 route show default | awk 'NR == 1 { for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }')"
  fi
  if [ -z "$outbound_interface" ]; then
    echo "L2TP NAT: no IPv4 default-route interface found; set L2TP_NAT_INTERFACE" >&2
    exit 1
  fi
  if ! ip link show dev "$outbound_interface" >/dev/null 2>&1; then
    echo "L2TP NAT: interface $outbound_interface does not exist" >&2
    exit 1
  fi
  if ! iptables -t nat -C POSTROUTING -s "$client_subnet" -o "$outbound_interface" -j MASQUERADE 2>/dev/null; then
    iptables -t nat -A POSTROUTING -s "$client_subnet" -o "$outbound_interface" -j MASQUERADE
  fi
  echo "L2TP NAT enabled: $client_subnet via $outbound_interface"
fi

exec /usr/local/bin/l2tp-go "$@"
