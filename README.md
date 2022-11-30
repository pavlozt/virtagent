# VirtAgent #
A program for simulating large networks with low resource consumption.
Suitable for benchmarking network monitoring systems.

Can be used for benchmarking monitoring systems and various network experiments.
Some realistic network performance statistics are supported - packet loss percentage, delay normal distribution, and setting a value of its standard deviation.
Simulation happens by capturing and sending packets.

For 16384 hosts, the program consumes 332.5Mb memory (20Kb per gorutine).



#  Example of use #
A small demonstration of work in a docker environment (assume you  clone source code.)
Up docker-compose project with terminal and ping 254 generated (fping -g) addresses in parallel:
```
docker compose build
docker compose run netshell bash
```
then run :
```
fping -s -g 172.30.0.1 172.30.0.10
```
Or nmap scan :
```
nmap -sn -PE 172.30.0.0/24
```
>(-sn for disable port scan, -PE for ping echo)

To assemble your stand for automatic testing, you need to add a virtual network setting to the containers,
namely running `ip route` commands. Examples of such settings are in the file [entrypoint.sh](./network-tools/entrypoint.sh)

# Limitations #
In the current version, the program can only simulate ping echo responses. IPv6 not yet supported.

Feel free to fork the repository and change the handler logic for your experiments.
By choosing the GO language, concurent programming will be easy. Or I can implement the logic you need.
Unfortunately, full-fledged imitation of the TCP stack is quite difficult. TCP support is unlikely to appear, but UDP or SNMP will not be a problem.

# License #

MIT
