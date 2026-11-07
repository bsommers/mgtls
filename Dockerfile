# Multi-stage zero-CGO static build for mgtls
# Pin a patched toolchain (go.mod `toolchain` directive must match; govulncheck clean).
FROM golang:1.26.10-alpine AS builder

WORKDIR /workspace
COPY go.mod go.sum ./
COPY src/ ./src/

RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mgtls ./src/cmd/mgtls \
 && mkdir -p /out/data && chmod 0700 /out/data

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/mgtls /usr/local/bin/mgtls
COPY --from=builder --chown=65532:65532 /out/data /data

# Run as an unprivileged user: the CA store holds private keys and must not be root-owned
# in a writable volume, and the process never needs root inside a scratch image.
USER 65532:65532
WORKDIR /data
ENV MGTLS_STORE_DIR=/data/.mgtls

ENTRYPOINT ["/usr/local/bin/mgtls"]
CMD ["--help"]
