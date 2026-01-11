#!/bin/sh
# Run gosmb tests in privileged Alpine container
# Uses host kernel modules (ksmbd must be available on host)

set -e

cd "$(dirname "$0")"

# Detect docker compose command (v2 plugin vs v1 standalone)
if docker compose version >/dev/null 2>&1; then
    COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE="docker-compose"
else
    echo "Error: docker compose not found"
    echo "Install docker-compose or Docker Compose v2 plugin"
    exit 1
fi

case "${1:-test}" in
    test)
        echo "Running tests in container..."
        $COMPOSE build test
        $COMPOSE run --rm test
        ;;
    shell)
        echo "Opening shell in container..."
        $COMPOSE build shell
        $COMPOSE run --rm shell
        ;;
    build)
        echo "Building container..."
        $COMPOSE build
        ;;
    *)
        echo "Usage: $0 [test|shell|build]"
        exit 1
        ;;
esac
