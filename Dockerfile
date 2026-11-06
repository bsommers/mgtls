# Multi-stage zero-CGO static build for mgtls
FROM golang:1.26-alpine AS builder

WORKDIR /workspace
COPY go.mod go.sum ./
COPY src/ ./src/

RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mgtls ./src/cmd/mgtls

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/mgtls /usr/local/bin/mgtls

WORKDIR /data
ENV MGTLS_STORE_DIR=/data/.mgtls

ENTRYPOINT ["/usr/local/bin/mgtls"]
CMD ["--help"]
