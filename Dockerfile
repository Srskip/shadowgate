# Build stage
FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Copy go mod files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build with version info
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o shadowgate ./cmd/shadowgate

# Runtime stage
FROM scratch

# Copy CA certificates for HTTPS backends
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy binary
COPY --from=builder /build/shadowgate /shadowgate

# Default config location
VOLUME ["/etc/shadowgate"]

# Default ports
EXPOSE 8080 8443

ENTRYPOINT ["/shadowgate"]
CMD ["-config", "/etc/shadowgate/config.yaml"]
