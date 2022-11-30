#!/bin/sh
if [[ -z "$IP_ROUTE" ]]; then
    echo "Forgot setup route ? " 1>&2
fi
/sbin/ip route add $IP_ROUTE via $IP_GATEWAY
exec "$@"
