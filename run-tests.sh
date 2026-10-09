#!/bin/sh
set -e

trap 'docker compose down' EXIT

docker compose down
docker compose up -d --wait --wait-timeout 180

go test -failfast -race -cover -v -run Integration -coverprofile=coverage-integration.out -covermode=atomic
