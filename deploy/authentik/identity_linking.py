"""Authenticator-owned immutable linking; rendered as an OAuth source mapping.

The source mapping runs AFTER gateway token/UserInfo verification but BEFORE
Authentik chooses authentication versus user-initiated linking. It returns no
user attributes and never creates a User or assigns permissions.
"""
import base64
import re


def decode_base64(value, urlsafe=False):
    pattern = r"[A-Za-z0-9_-]+" if urlsafe else r"[A-Za-z0-9+/]+"
    if not isinstance(value, str) or not re.fullmatch(pattern, value) or len(value) > 1200:
        raise ValueError("Invalid identity encoding")
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_" if urlsafe else None, validate=True)
    encoded = (base64.urlsafe_b64encode(raw) if urlsafe else base64.b64encode(raw)).decode().rstrip("=")
    if encoded != value:
        raise ValueError("Noncanonical identity encoding")
    return raw


def decode_subject(subject, trusted_account, trusted_connector):
    if not isinstance(subject, str) or len(subject) > 1400:
        raise ValueError("Invalid identity subject")
    parts = subject.split(":")
    if len(parts) != 3 or parts[0] != "netbird":
        raise ValueError("Invalid identity subject")
    account = decode_base64(parts[1], True).decode("utf-8")
    if account != trusted_account:
        raise ValueError("Untrusted NetBird account")
    principal = decode_base64(parts[2], True).decode("ascii")
    raw = decode_base64(principal)
    # Authentik's hashed_user_id is 64 lowercase hex bytes. Dex wraps it as
    # protobuf field 1 and the connector ID as field 2. Require exactly those
    # canonical fields, rejecting duplicates, unknown fields, aliases and tails.
    if len(raw) < 68 or raw[:2] != b"\x0a\x40":
        raise ValueError("Not a federated Authentik user")
    uid = raw[2:66].decode("ascii")
    if not re.fullmatch(r"[0-9a-f]{64}", uid):
        raise ValueError("Invalid Authentik subject")
    connector = trusted_connector.encode("ascii")
    if not 1 <= len(connector) < 128 or raw[66:] != b"\x12" + bytes([len(connector)]) + connector:
        raise ValueError("Untrusted identity connector or malformed identity")
    return uid


def link_identity(source, info, trusted_account, trusted_connector, authentik_client_id):
    from django.db import transaction
    from authentik.core.models import User
    from authentik.providers.oauth2.models import OAuth2Provider
    from authentik.sources.oauth.models import UserOAuthSourceConnection

    if source.slug != "netbird" or source.user_matching_mode != "identifier" or source.enrollment_flow_id is not None:
        raise ValueError("Unexpected source configuration")
    # Subject-mode changes must not silently change identity semantics.
    provider = OAuth2Provider.objects.get(client_id=authentik_client_id)
    if provider.sub_mode != "hashed_user_id":
        raise ValueError("Unsupported upstream subject mode")
    identifier = info.get("sub")
    uid = decode_subject(identifier, trusted_account, trusted_connector)
    with transaction.atomic():
        # Read current users on every login. No username/email match, attributes,
        # stale user cache or user-supplied account-selection input participates.
        candidates = [u for u in User.objects.filter(is_active=True, type="internal").exclude(username="AnonymousUser").only("id", "uuid", "is_active", "type") if u.uid == uid]
        if len(candidates) != 1:
            raise ValueError("No unique active Authentik user for this identity")
        user = User.objects.select_for_update().get(pk=candidates[0].pk)
        if not user.is_active or user.type != "internal" or user.uid != uid:
            raise ValueError("Authentik user is no longer eligible")
        connection, _ = UserOAuthSourceConnection.objects.get_or_create(
            source=source, identifier=identifier, defaults={"user": user})
        if connection.user_id != user.pk:
            raise ValueError("Refusing conflicting source identity link")
    return {}
