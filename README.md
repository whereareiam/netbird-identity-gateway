# NetBird Identity Gateway

NetBird Identity Gateway is a small, self-hosted OIDC broker for applications
behind a trusted reverse proxy. It can automatically authenticate a request
when a trusted proxy supplies a mapped identity, and it can fall back to a
normal browser-based login at any OIDC provider.

The default header names are compatible with the NetBird reverse proxy
(`X-NetBird-User` and `X-NetBird-Groups`), but both are configurable. The
gateway is not NetBird-specific and can be used with any proxy that can make
the identity headers trustworthy.

## Features

- OIDC discovery, authorization-code flow, token endpoint, UserInfo, and JWKS.
- Trusted-header auto-login for private network or service-mesh gateways.
- Upstream OIDC fallback for users without a trusted identity.
- Explicit source-to-canonical-identity mappings.
- Configurable groups and application claims.
- Forward-auth verification endpoint for legacy applications.
- One-time, short-lived authorization codes and signed RS256 tokens.
- Secure HTTP defaults, structured request logging, and health checks.
- Distroless container image and race-tested Go code.

## Security model

Trusted headers are authentication credentials. The gateway only accepts them
when the direct TCP peer is within `trusted_proxy_cidrs`; it does not trust
`X-Forwarded-For` to make this decision. Put the gateway on a private network,
use mTLS or a service-mesh policy between the proxy and gateway, and ensure no
alternate ingress can reach the gateway or the backend while retaining identity
headers.

The gateway strips no headers from an upstream application because it is not a
reverse proxy. A fronting proxy must strip client-provided identity headers
before adding its own. Unknown trusted identities are rejected by default.
Use immutable canonical subjects in mappings and keep application authorization
inside each application.

The in-memory code, session, and token stores are intentionally simple for the
initial release. Run a single replica or provide sticky routing until a shared
store implementation is added. Mount a stable signing key in production;
otherwise every restart invalidates the published JWKS and tokens.

## Configuration

Copy [`config/config.example.yaml`](config/config.example.yaml) and edit it.
The upstream provider's callback must be registered as:

```text
https://identity.example.com/oauth2/callback
```

Each downstream application is registered under `clients`. Its OIDC issuer is
the gateway URL, for example:

```text
Issuer:        https://identity.example.com
Authorization: https://identity.example.com/oauth2/authorize
Token:         https://identity.example.com/oauth2/token
JWKS:          https://identity.example.com/oauth2/jwks.json
```

The gateway's own authorization endpoint accepts `client_id`, `redirect_uri`,
`response_type=code`, `scope`, `state`, and `nonce`. Applications should use
the authorization-code flow and validate the ID token according to OIDC.

For a legacy reverse-proxy integration, call `/auth/verify`. A successful
response contains `X-Identity-Subject`, `X-Identity-Email`,
`X-Identity-Name`, `X-Identity-Preferred-Username`, and
`X-Identity-Groups` response headers. Only copy these headers to the backend
after the gateway returns HTTP 200.

## Run locally

```bash
go run ./cmd/netbird-identity-gateway -config config/config.example.yaml
```

The example config requires a reachable upstream OIDC provider. For unit tests
and container builds:

```bash
make test
make test-race
make docker-build
```

## License

Copyright 2026 whereareiam and contributors.

Licensed under the GNU Affero General Public License, version 3 or later. See
[`LICENSE`](LICENSE).
