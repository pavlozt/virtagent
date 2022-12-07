#!/bin/bash

function composeLogs {
	echo "Compose logs:"
	docker compose -p virtagenttest logs --tail 10
	echo "Compose logs end"
}

docker compose -p virtagenttest exec netshell fping -g 172.30.0.1 172.30.0.20 -qs  >& exec.test

cat exec.test

if ! grep -q "10 alive" exec.test ; then
	echo required 10 alive hosts not found
	composeLogs
	exit 1
fi
if ! grep -q "10 unreachable" exec.test ; then
	echo required 10 unreachable hosts not found
	composeLogs
	exit 1
fi
echo "Output tested."
composeLogs


