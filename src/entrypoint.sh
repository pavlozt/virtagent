#!/bin/sh
if [[ -z "$SIMULATE_NETWORK" ]]; then
    echo "Must provide SIMULATE_NETWORK in environment" 1>&2
    exit 1
fi

# To bypass various strange behavior of docker network stack just remove all of IP
/sbin/ip addr flush dev eth0

if [[ -z "$SIMULATE_ROUTER" ]]; then
    exec /app -iface eth0  -iprange $SIMULATE_NETWORK "$@"
else
    exec /app -iface eth0  -simulaterouter $SIMULATE_ROUTER -iprange $SIMULATE_NETWORK "$@"
fi
