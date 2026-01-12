#!/bin/sh
# Run gosmb tests in privileged Alpine container
# Uses host kernel modules (ksmbd must be available on host)
#
# Usage:
#   ./test-docker.sh              # Run tests
#   ./test-docker.sh -v           # Run tests with verbose output
#   ./test-docker.sh -race        # Run tests with race detector
#   ./test-docker.sh -v -race     # Combined flags
#   ./test-docker.sh shell        # Open interactive shell

set -e

cd "$(dirname "$0")"

# Image name with hash suffix for cache invalidation
IMAGE_BASE="gosmb-test"
DOCKERFILE_HASH=$(sha256sum Dockerfile | cut -c1-8)
IMAGE_NAME="${IMAGE_BASE}:${DOCKERFILE_HASH}"

# Build image if it doesn't exist
build_if_needed() {
    if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
        echo "Building container image ${IMAGE_NAME}..."
        docker build -t "$IMAGE_NAME" .
    fi
}

# Run container with source and caches mounted
run_container() {
    docker run --rm \
        --privileged \
        --pid=host \
        --network=host \
        -v /lib/modules:/lib/modules:ro \
        -v /tmp:/tmp \
        -v "$(pwd)":/app \
        -v gosmb-modcache:/go/pkg/mod \
        -v gosmb-buildcache:/root/.cache/go-build \
        "$@"
}

# Check for shell command
if [ "$1" = "shell" ]; then
    build_if_needed
    echo "Opening shell in container..."
    run_container -it "$IMAGE_NAME" /bin/sh
    exit 0
fi

# Default: run tests with any provided arguments
build_if_needed
run_container "$IMAGE_NAME" go test "$@" ./...
