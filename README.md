# NetBird Identity Gateway

An identity-only OIDC source for Authentik. NetBird proves which principal is
connecting; Authentik owns users, account status, application access, groups and
application entitlements. Applications continue using their Authentik issuers.

The gateway emits only an immutable `sub` and protocol claims. It has no user
registration, email matching, groups, application roles, fallback login, browser
sessions, refresh tokens or forward-auth endpoint. Old broker configurations are
rejected by strict YAML parsing.

## Connect Authentik

1. Build the gateway and the [NetBird proxy extension](deploy/netbird/Dockerfile).
   The extension is pinned to upstream v0.77.1 commit
   `79a06720b684768b421f0a54f3bb14f22704994f`. It strips incoming
   `X-NetBird-Principal` and replaces it with the verified `base64url(accountID):base64url(principalID)`.
   Set `NB_PROXY_IDENTITY_DOMAIN` to the gateway host. The proxy makes a fresh
   management validation on every identity request and checks peer-key stability,
   so cached IP identities cannot authenticate a reassigned peer. The standard `X-NetBird-User` display header is never accepted for login.
2. Mount a stable RSA private key (at least 2048 bits) and a configuration based
   on [the example](config/config.example.yaml). Configure exactly one confidential
   client for Authentik and explicitly allow only the NetBird human principal IDs
   you will link. A machine peer or a renamed/reassigned email is not a user link.
3. Expose port 8080 only to the authenticated NetBird proxy. Expose port 8081 only
   to Authentik over authenticated infrastructure transport. Enforce this using
   NetworkPolicy and, where available, mesh mTLS; CIDR checking alone does not
   establish proxy identity. Never expose the authorization listener through a
   shared ingress that can preserve arbitrary identity headers.
4. Create an Authentik OpenID Connect source with `pkce: S256`, Basic client
   authentication and scopes `*openid`. Use the external gateway URL for the
   authorization endpoint. Configure the token, UserInfo and JWKS endpoints on
   the protected backchannel. The discovery document is on the backchannel;
   deployments using different transport URLs must override those endpoint URLs.
5. Pre-create source connections linking `netbird:<accountID>:<principalID>` to
   existing Authentik users. Use identifier matching, disable enrollment, and
   configure no user or group import mappings. Do not link by email. Keep source
   authentication free of user-write/group-import stages.
6. Select this source in the application's Authentik authentication flow while
   retaining its authorization policies and property mappings. Keep applications
   pointed at Authentik. Do not configure Authentik as a gateway fallback.

A Bulwark login follows Bulwark → Authentik → gateway → Authentik → Bulwark.
Authentik evaluates Bulwark access and emits Bulwark's application entitlements.
Stalwart continues receiving Authentik-issued tokens. Existing sessions and tokens
retain their configured lifetimes; automatic login is not instantaneous revocation
of sessions already created by downstream applications.

## Operate the gateway

Run a separate Deployment with one replica. Pending authorization codes are held
in a bounded in-memory store; a restart invalidates them, and a login can be
retried. Multiple replicas require shared code storage and are not supported.
Use `Recreate` during rollout to avoid splitting code issuance and redemption.

Mount the signing key and client secret using Kubernetes Secrets. Run nonroot,
with a read-only root filesystem, dropped capabilities, resource limits and no
service-account token. Both listeners have `/healthz`; the backchannel cannot
accept identity headers or issue authorization codes.

The gateway supports authorization-code flow, exact HTTPS callbacks, mandatory
S256 PKCE, single-use codes, RS256 ID/access tokens and UserInfo. It accepts only
`openid`. Nonce is echoed when supplied; it is optional for compatibility with
Authentik's code flow. Tokens default to 60 seconds and have separate ID/access
purposes. UserInfo returns only `sub` and rejects ID tokens.

Requests with unknown principals fail closed with 403; invalid OAuth requests
return 400. An exhausted code store returns 503. There is no interactive fallback.
Logs contain method/path/duration, without headers, tokens or query strings.

## Build and publish

```sh
make test-race
make lint
make docker-build
```

Pushes to `dev` run tests and publish gateway and proxy images through the existing
GitHub OIDC registry workflow. Each receives an immutable `dev-<commit>` tag and
an overwritable `dev` tag under `registry.whereareiam.me/images/whereareiam/`.
Deploy by digest when possible so rollback does not depend on the mutable tag.

## License

Copyright 2026 whereareiam and contributors. AGPL-3.0-or-later; see [LICENSE](LICENSE).
The proxy extension builds NetBird's upstream source and preserves its image layout.
