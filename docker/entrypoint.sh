#!/bin/sh
set -eu

# Keep flag-only invocations and the old executable/configuration names working.
case "${1:-}" in
  server) shift ;;
  client|--help|-h) exec /usr/local/bin/overture-vpn "$@" ;;
  -*) ;;
  "") ;;
  *) exec /usr/local/bin/overture-vpn "$@" ;;
esac

config_value() {
  key="$1"
  shift
  /usr/local/bin/overture-vpn server "$@" --print-config-value "$key"
}

if [ "$(config_value nat.enabled "$@")" = "true" ]; then
  client_subnet="$(config_value network.subnet "$@")"
  outbound_interface="$(config_value nat.interface "$@")"
  if [ -z "$outbound_interface" ]; then
    outbound_interface="$(ip -4 route show default | awk 'NR == 1 { for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }')"
  fi
  if [ -z "$outbound_interface" ]; then
    echo "Overture NAT: no IPv4 default-route interface found; set nat.interface" >&2
    exit 1
  fi
  if ! ip link show dev "$outbound_interface" >/dev/null 2>&1; then
    echo "Overture NAT: interface $outbound_interface does not exist" >&2
    exit 1
  fi
  if ! iptables -t nat -C POSTROUTING -s "$client_subnet" -o "$outbound_interface" -j MASQUERADE 2>/dev/null; then
    iptables -t nat -A POSTROUTING -s "$client_subnet" -o "$outbound_interface" -j MASQUERADE
  fi
  echo "Overture NAT enabled: $client_subnet via $outbound_interface"
fi

exec /usr/local/bin/overture-vpn server "$@"
