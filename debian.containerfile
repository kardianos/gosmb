# Dockerfile for gosmb integration tests (Debian-based)
# Requires: docker run --privileged with access to host kernel modules

FROM golang:1.25.5-trixie

# Install required packages
# build-essential provides gcc for cgo (needed for -race)
# krb5-user provides kinit/klist/kvno for Kerberos testing
# smbclient for SMB client testing
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    smbclient \
    kmod \
    iproute2 \
    procps \
    util-linux \
    fuse3 \
    krb5-user \
    && rm -rf /var/lib/apt/lists/*

ENV CGO_ENABLED=1

WORKDIR /app
