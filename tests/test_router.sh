#!/bin/bash

docker exec router-netshell-1 fping -g 172.30.0.1 172.30.0.20 -qs 2> exec_result.txt

cat exec_result.txt

if ! grep -q "10 alive" exec_result.txt ; then
	echo required 10 alive hosts not found
	exit 1
fi
if ! grep -q "10 unreachable" exec_result.txt ; then
	echo required 10 unreachable hosts not found
	exit 1
fi


