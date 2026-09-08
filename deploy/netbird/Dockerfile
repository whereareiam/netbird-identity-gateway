FROM golang:1.26.7-alpine AS build
RUN apk add --no-cache git patch
WORKDIR /src
RUN git clone --depth 1 --branch v0.77.1 https://github.com/netbirdio/netbird.git . && test "$(git rev-parse HEAD)" = "79a06720b684768b421f0a54f3bb14f22704994f"
COPY deploy/netbird/principal.patch /tmp/principal.patch
RUN patch -p1 < /tmp/principal.patch
RUN go test ./proxy/internal/proxy ./proxy/internal/auth -run "TestStampNetBirdPrincipal|TestIdentityDomainRevalidatesPrincipal" -count=1
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.Version=0.77.1-identity-dev" -o /netbird-proxy ./proxy/cmd/proxy
FROM netbirdio/reverse-proxy:0.77.1
COPY --from=build /netbird-proxy /go/bin/netbird-proxy
