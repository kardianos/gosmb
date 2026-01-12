# Dockerfile for gosmb integration tests
# Requires: docker run --privileged with access to host kernel modules

FROM golang:1.25-alpine

# Install required packages
# build-base provides gcc/musl-dev for cgo (needed for -race)
RUN apk add --no-cache \
    build-base \
    samba-client \
    kmod \
    iproute2 \
    procps \
    util-linux \
    fuse3

ENV CGO_ENABLED=1

WORKDIR /app
