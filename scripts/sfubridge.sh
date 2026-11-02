#!/usr/bin/env bash
# Free Turn Proxy - запуск sfubridge для клиентов с -provider sfu.
# Конфиг - /etc/default/freeturn-sfubridge (source-ится), см. docs/sfu.md.
#
# По умолчанию мост ходит в VK напрямую с адреса сервера, как и TURN-режим. SFU_WARP=1
# уводит его в netns с Cloudflare WARP: VK видит адрес Cloudflare, ценой пинга.
set -euo pipefail

CONF=${SFU_CONF:-/etc/default/freeturn-sfubridge}
# shellcheck disable=SC1090
[[ -f $CONF ]] && . "$CONF"

SFU_BIN=${SFU_BIN:-/usr/local/bin/sfubridge}
SFU_PORT=${SFU_PORT:-56000}
SFU_WARP=${SFU_WARP:-0}
SFU_WARP_PROFILE=${SFU_WARP_PROFILE:-/etc/freeturn/wgcf-profile.conf}
SFU_EXTRA=${SFU_EXTRA:-}

NS=ft-sfu
WG_IF=ft-warp
VETH=ft-sfu0
HOST_IP=10.77.0.1
NS_IP=10.77.0.2

warp_down() {
	ip netns del "$NS" 2>/dev/null || true
	ip link del "$VETH" 2>/dev/null || true
	ip link del "$WG_IF" 2>/dev/null || true
}

# Поле [Interface] из профиля wgcf: адреса через запятую, MTU.
profile_field() {
	sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$SFU_WARP_PROFILE" | head -n1
}

warp_up() {
	[[ -f $SFU_WARP_PROFILE ]] || { echo "sfubridge: нет профиля WARP $SFU_WARP_PROFILE" >&2; exit 1; }
	warp_down
	ip netns add "$NS"
	ip -n "$NS" link set lo up

	# wg-quick не годится: он правит маршруты хоста. Интерфейс создаётся снаружи и уезжает
	# в netns - UDP-сокет WireGuard остаётся в сети хоста, а всё изнутри netns идёт в WARP.
	ip link add "$WG_IF" type wireguard
	wg setconf "$WG_IF" <(wg-quick strip "$SFU_WARP_PROFILE")
	ip link set "$WG_IF" netns "$NS"
	local addr
	IFS=',' read -ra addrs <<<"$(profile_field Address)"
	for addr in "${addrs[@]}"; do
		ip -n "$NS" addr add "${addr// /}" dev "$WG_IF"
	done
	local mtu
	mtu=$(profile_field MTU)
	ip -n "$NS" link set "$WG_IF" mtu "${mtu:-1280}" up
	ip -n "$NS" route add default dev "$WG_IF"
	ip -n "$NS" -6 route add default dev "$WG_IF" 2>/dev/null || true

	# Обратный путь к серверу на хосте. Наружу netns ходит только через WARP.
	ip link add "$VETH" type veth peer name ft-sfu1
	ip link set ft-sfu1 netns "$NS"
	ip addr add "$HOST_IP/30" dev "$VETH"
	ip link set "$VETH" up
	ip -n "$NS" addr add "$NS_IP/30" dev ft-sfu1
	ip -n "$NS" link set ft-sfu1 up
}

case ${1:-run} in
run)
	[[ -n ${SFU_ROOM:-} ]] || { echo "sfubridge: SFU_ROOM не задан в $CONF" >&2; exit 1; }
	# shellcheck disable=SC2086
	if [[ $SFU_WARP == 1 ]]; then
		warp_up
		exec ip netns exec "$NS" "$SFU_BIN" -room "$SFU_ROOM" -forward "$HOST_IP:$SFU_PORT" $SFU_EXTRA
	fi
	warp_down
	# shellcheck disable=SC2086
	exec "$SFU_BIN" -room "$SFU_ROOM" -forward "127.0.0.1:$SFU_PORT" $SFU_EXTRA
	;;
warp-down)
	warp_down
	;;
*)
	echo "usage: $0 [run|warp-down]" >&2
	exit 2
	;;
esac
