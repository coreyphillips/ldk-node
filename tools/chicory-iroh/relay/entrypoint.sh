#!/bin/sh
set -eu
# This container alone has NET_ADMIN. The endpoint runs as an unprivileged user.
# Docker's embedded DNS may use a translated local port, so allow its local IP.
iptables -N CHICORY_RELAY_ONLY
iptables -A CHICORY_RELAY_ONLY -d 127.0.0.11/32 -j ACCEPT
iptables -A CHICORY_RELAY_ONLY -j DROP
iptables -I OUTPUT 1 -p udp -m owner --uid-owner 1000 -j CHICORY_RELAY_ONLY
ip6tables -N CHICORY_RELAY_ONLY
ip6tables -A CHICORY_RELAY_ONLY -j DROP
ip6tables -I OUTPUT 1 -p udp -m owner --uid-owner 1000 -j CHICORY_RELAY_ONLY
exec su-exec node:node node /app/worker.cjs
