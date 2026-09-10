# NetBird proxy and client builds

This directory builds NetBird v0.77.1 with the identity handoff and signal
registration recovery patches. The upstream commit is pinned in the Dockerfile.
The identity gateway remains a separate application; these patches do not issue
application entitlements or change Authentik authorization.

## Build

```sh
docker build -f deploy/netbird/Dockerfile --target proxy -t netbird-identity-proxy:dev .
docker build -f deploy/netbird/Dockerfile --target client -t netbird-client:0.77.1-arcadeya.2 .
```

Run these commands from the repository root. The build runs the identity handoff
and registration regression tests. The client target contains the standard
NetBird container entrypoint and a patched `/usr/local/bin/netbird` binary.
The proxy target is the default final stage.

## Recover signal connections

Signal registration has a 15-second timeout. It covers the interval before the
server sends its registration header, when the receive watchdog is not running
yet. A timeout cancels that attempt and lets the existing retry loop reconnect.
It does not set a deadline on the established stream or cancel the parent client.

Health checks require the receive stream to be registered. A ready HTTP/2
connection alone is insufficient. The registration flag uses atomic access
because health checks and connection recovery run concurrently.

For the proxy, use `/healthz/startup` for readiness and a tolerant liveness check.
Despite its name, this endpoint checks the embedded client's current management,
signal and relay status on every request. `/healthz/live` only proves the HTTP
process is alive; `/healthz/ready` only checks the outer management connection.
Allow enough consecutive liveness failures for ordinary control-plane outages
before restarting. These checks do not prove every remote peer or backend is reachable.

## Retain and clean up peers

Give each routing replica its own persistent `/var/lib/netbird` directory and
prevent concurrent containers from using one identity. When migrating an existing
peer, retain `default.json` and `active_profile.json`; do not copy transient
`state.json` network-cleanup state between network namespaces.

The reverse proxy intentionally creates ephemeral embedded peers. Its data volume
does not make their WireGuard keys persistent. Healthy disconnect processing lets
NetBird garbage-collect old registrations after its grace period. A management
server crash can leave persistent connection flags behind; recovery must account
for the actual management deployment and must not reset another live server's sessions.

On Kubernetes hosts where Calico and NetBird compete for loopback XDP attachment,
set `NB_DISABLE_EBPF_WG_PROXY=true` in the host NetBird service environment.
This selects NetBird's standard UDP adapter while retaining WireGuard and relay
access controls. Pod-local interfaces and non-Kubernetes hosts need separate assessment.
