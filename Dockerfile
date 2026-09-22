FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /directory ./cmd/did-directory
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /dimocli ./cmd/dimocli
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /org-host ./cmd/org-host

FROM alpine:3.21 AS directory
COPY --from=builder /directory /usr/local/bin/directory
ENTRYPOINT ["directory"]
CMD ["-settings", "/config/settings.yaml"]

FROM alpine:3.21 AS cli
COPY --from=builder /dimocli /usr/local/bin/dimocli
ENTRYPOINT ["dimocli"]

FROM alpine:3.21 AS org-host
COPY --from=builder /org-host /usr/local/bin/org-host
ENTRYPOINT ["org-host"]
CMD ["-settings", "/config/org-host.yaml"]
