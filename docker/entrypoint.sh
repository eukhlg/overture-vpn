#!/bin/sh
set -eu

if [ "${L2TP_NAT_ENABLED:-true}" = "true" ]; then
  client_subnet="${L2TP_CLIENT_SUBNET:-10.0.0.0/24}"
  outbound_interface="${L2TP_NAT_INTERFACE:-eth0}"
  iptables -t nat -A POSTROUTING -s "$client_subnet" -o "$outbound_interface" -j MASQUERADE
fi

exec /usr/local/bin/l2tp-go "$@"
