# Dockerfile for gosmb integration tests
# Requires: docker run --privileged with access to host kernel modules

FROM golang:1.24-alpine

# Install required packages
RUN apk add --no-cache \
    samba-client \
    kmod \
    iproute2 \
    procps \
    util-linux \
    fuse3

WORKDIR /app

# Copy go.mod first for better layer caching
COPY go.mod go.sum ./
RUN go mod download 2>/dev/null || true

# Copy source directories preserving structure
COPY smbsys/ ./smbsys/
COPY smbvfs/ ./smbvfs/

# Default command runs tests
CMD ["go", "test", "-v", "-count=1", "./..."]
