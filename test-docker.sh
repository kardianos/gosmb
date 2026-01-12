#!/bin/sh
# Run gosmb tests in privileged container
# Uses host kernel modules (ksmbd must be available on host)
#
# Usage:
#   ./test-docker.sh              # Run tests (Debian by default)
#   ./test-docker.sh -v           # Run tests with verbose output
#   ./test-docker.sh -race        # Run tests with race detector
#   ./test-docker.sh -v -race     # Combined flags
#   ./test-docker.sh shell        # Open interactive shell
#   CONTAINER=alpine ./test-docker.sh  # Use Alpine container

set -e

cd "$(dirname "$0")"

# Select containerfile: debian (default) or alpine
CONTAINER="${CONTAINER:-debian}"
CONTAINERFILE="${CONTAINER}.containerfile"

if [ ! -f "$CONTAINERFILE" ]; then
    echo "Error: $CONTAINERFILE not found"
    exit 1
fi

# Image name with hash suffix for cache invalidation
IMAGE_BASE="gosmb-test-${CONTAINER}"
DOCKERFILE_HASH=$(sha256sum "$CONTAINERFILE" | cut -c1-8)
IMAGE_NAME="${IMAGE_BASE}:${DOCKERFILE_HASH}"

# Build image if it doesn't exist
build_if_needed() {
    if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
        echo "Building container image ${IMAGE_NAME} from ${CONTAINERFILE}..."
        docker build -t "$IMAGE_NAME" -f "$CONTAINERFILE" .
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
        -v "gosmb-modcache-${CONTAINER}:/go/pkg/mod" \
        -v "gosmb-buildcache-${CONTAINER}:/root/.cache/go-build" \
        "$@"
}

# Check for shell command
if [ "$1" = "shell" ]; then
    build_if_needed
    echo "Opening shell in container..."
    run_container -it "$IMAGE_NAME" /bin/bash 2>/dev/null || run_container -it "$IMAGE_NAME" /bin/sh
    exit 0
fi

# Default: run tests with any provided arguments
build_if_needed
run_container "$IMAGE_NAME" go test "$@" ./...
