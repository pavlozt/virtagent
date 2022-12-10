#!/bin/sh
if [[ -z "$SIMULATE_NETWORK" ]]; then
    echo "Must provide SIMULATE_NETWORK in environment" 1>&2
    exit 1
fi

# When debugging, we can't totally remove IP.
# This can cause network problems in Docker Desktop on Windows
#/sbin/ip addr flush dev eth0

if [[ -z "$SIMULATE_ROUTER" ]]; then
    exec /go/bin/dlv --listen=:4000 --headless=true --log=true --accept-multiclient --api-version=2 exec /app -- -iface eth0 -iprange -iprange $SIMULATE_NETWORK "$@"
else
    exec /go/bin/dlv --listen=:4000 --headless=true --log=true --accept-multiclient --api-version=2 exec /app -- -iface eth0 -simulaterouter $SIMULATE_ROUTER -iprange $SIMULATE_NETWORK "$@"
fi
