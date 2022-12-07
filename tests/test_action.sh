#!/bin/bash

docker compose -p virtagenttest exec netshell fping -g 172.30.0.1 172.30.0.20 -qs 2> exec.test

cat exec.test

if ! grep -q "10 alive" exec.test ; then
	echo required 10 alive hosts not found
	exit 1
fi
if ! grep -q "10 unreachable" exec.test ; then
	echo required 10 unreachable hosts not found
	exit 1
fi


