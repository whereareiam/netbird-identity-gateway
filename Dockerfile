FROM golang:1.26.7-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.version=${VERSION}" -o /netbird-identity-gateway ./cmd/netbird-identity-gateway

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /netbird-identity-gateway /usr/bin/netbird-identity-gateway

USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/bin/netbird-identity-gateway"]
