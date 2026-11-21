# Cross-compiles on the build host for each target platform, so multi-arch
# builds (amd64, arm64, arm/v7) don't run the Go toolchain under emulation.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
ARG TARGETOS TARGETARCH TARGETVARIANT
ARG MARCO_BUILD_VERSION=dev
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN case "$MARCO_BUILD_VERSION" in *[!a-zA-Z0-9._+-]*) echo "invalid MARCO_BUILD_VERSION" >&2; exit 1;; esac && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags="-s -w -X main.version=$MARCO_BUILD_VERSION" -o /out/marco ./cmd/marco && \
    mkdir -p -m 0700 /out/var/lib/marco && \
    mkdir -p /out/runtime/tmp && chmod 1777 /out/runtime/tmp

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=build /out/marco /marco
# Marco looks for catalog/services.json next to its executable.
COPY --from=build /src/catalog /catalog
COPY --from=build --chown=65532:65532 /out/var/lib/marco /var/lib/marco
# Copy the parent tree to preserve the sticky bit on SQLite's temporary directory.
COPY --from=build /out/runtime/ /
USER 65532:65532
# DNS (53/udp, 53/tcp inside the container) and the HTTPS admin console. The
# ports are whatever marco.json binds; these are the conventional ones.
EXPOSE 53/udp 53/tcp 8443/tcp
ENTRYPOINT ["/marco"]
CMD ["run", "--config", "/etc/marco/marco.json"]
