#!/bin/bash

docker compose -f "../docker-compose.yml" -p virtagenttest up -d --build
./test_action.sh
docker compose -f "../docker-compose.yml" -p virtagenttest down


