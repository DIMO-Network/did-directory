FROM golang:1.25 AS build

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /did-directory ./cmd/did-directory

FROM gcr.io/distroless/base:nonroot

COPY --from=build /did-directory /did-directory

USER nonroot:nonroot

EXPOSE 8080

ENTRYPOINT ["/did-directory"]
CMD ["-settings", "/config/settings.yaml"]
