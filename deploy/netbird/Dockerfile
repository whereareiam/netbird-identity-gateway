FROM golang:1.26.7-alpine AS build
RUN apk add --no-cache git patch
WORKDIR /src
RUN git clone --depth 1 --branch v0.77.1 https://github.com/netbirdio/netbird.git . && test "$(git rev-parse HEAD)" = "79a06720b684768b421f0a54f3bb14f22704994f"
COPY deploy/netbird/principal.patch /tmp/principal.patch
COPY deploy/netbird/recovery.patch /tmp/recovery.patch
RUN patch -p1 < /tmp/principal.patch && patch -p1 < /tmp/recovery.patch
RUN go test ./shared/signal/client -run "TestRegistration|TestReceiveProbeRoundTrips" -count=1
RUN go test ./proxy/internal/proxy ./proxy/internal/auth -run "TestStampNetBirdPrincipal|TestIdentityDomainRevalidatesPrincipal" -count=1
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.Version=0.77.1-identity-dev" -o /netbird-proxy ./proxy/cmd/proxy
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/netbirdio/netbird/version.version=0.77.1-arcadeya.2" -o /netbird-client ./client
FROM netbirdio/netbird:0.77.1 AS client
COPY --from=build /netbird-client /usr/local/bin/netbird
FROM netbirdio/reverse-proxy:0.77.1 AS proxy
COPY --from=build /netbird-proxy /go/bin/netbird-proxy
