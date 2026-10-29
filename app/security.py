import base64
import json
from dataclasses import dataclass
from functools import lru_cache
from typing import Callable, Optional

from fastapi import Depends, Header, HTTPException, status

from app.config import settings

try:
    import jwt
    from jwt import PyJWKClient
except Exception:  # pragma: no cover - surfaced by runtime checks
    jwt = None
    PyJWKClient = None


@dataclass
class Principal:
    username: str
    roles: list[str]
    tenant_code: str
    token_payload: dict


def _decode_jwt_payload(token: str) -> dict:
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("Malformed JWT")
    payload_part = parts[1]
    padding = "=" * (-len(payload_part) % 4)
    decoded = base64.urlsafe_b64decode(payload_part + padding)
    return json.loads(decoded.decode("utf-8"))


def _normalize_roles(raw_roles: list[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for role in raw_roles:
        chunk = role.strip().lower()
        if not chunk or chunk in seen:
            continue
        seen.add(chunk)
        normalized.append(chunk)
    return normalized


def _extract_roles(payload: dict) -> list[str]:
    roles: list[str] = []
    raw_roles = payload.get("roles", [])
    if isinstance(raw_roles, list):
        roles.extend(str(r) for r in raw_roles)

    realm_access = payload.get("realm_access", {})
    if isinstance(realm_access, dict):
        rr = realm_access.get("roles", [])
        if isinstance(rr, list):
            roles.extend(str(r) for r in rr)

    resource_access = payload.get("resource_access", {})
    if isinstance(resource_access, dict):
        for _client, data in resource_access.items():
            if isinstance(data, dict):
                cr = data.get("roles", [])
                if isinstance(cr, list):
                    roles.extend(str(r) for r in cr)

    return _normalize_roles(roles)


def _allowed_roles() -> set[str]:
    return set(_normalize_roles(settings.auth_allowed_roles.split(",")))


def _role_aliases() -> dict[str, str]:
    raw = settings.auth_role_aliases_json.strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    aliases: dict[str, str] = {}
    for raw_key, raw_value in parsed.items():
        if not isinstance(raw_key, str) or not isinstance(raw_value, str):
            continue
        key = raw_key.strip().lower()
        value = raw_value.strip().lower()
        if key and value:
            aliases[key] = value
    return aliases


def _map_roles(raw_roles: list[str]) -> list[str]:
    allowed = _allowed_roles()
    aliases = _role_aliases()
    mapped: list[str] = []
    seen: set[str] = set()
    for raw_role in _normalize_roles(raw_roles):
        canonical = aliases.get(raw_role, raw_role)
        if allowed and canonical not in allowed:
            continue
        if canonical in seen:
            continue
        seen.add(canonical)
        mapped.append(canonical)
    return mapped


def _extract_tenant_from_payload(payload: dict) -> Optional[str]:
    for claim in ("tenant_code", "tenant", "org", "organization"):
        value = payload.get(claim)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return None


def _jwt_algorithms() -> list[str]:
    configured = [chunk.strip() for chunk in settings.auth_jwt_algorithms.split(",") if chunk.strip()]
    return configured or ["RS256"]


@lru_cache(maxsize=8)
def _jwks_client(jwks_url: str):
    if not PyJWKClient:
        raise RuntimeError("PyJWT is required for verified JWT mode")
    return PyJWKClient(jwks_url)


def _decode_verified_jwt(token: str) -> dict:
    if not jwt:
        raise RuntimeError("PyJWT is required for verified JWT mode")

    jwks_url = settings.auth_jwks_url.strip()
    if not jwks_url:
        raise RuntimeError("SENTINEL_AUTH_JWKS_URL is required when verified JWT mode is enabled")

    signing_key = _jwks_client(jwks_url).get_signing_key_from_jwt(token)

    issuer = settings.keycloak_issuer.strip()
    audience = settings.keycloak_audience.strip()
    options = {
        "verify_signature": True,
        "verify_exp": True,
        "verify_nbf": True,
        "verify_iat": True,
        "verify_iss": bool(issuer),
        "verify_aud": bool(audience),
    }

    kwargs: dict = {
        "key": signing_key.key,
        "algorithms": _jwt_algorithms(),
        "options": options,
    }
    if issuer:
        kwargs["issuer"] = issuer
    if audience:
        kwargs["audience"] = audience

    return jwt.decode(token, **kwargs)


def get_current_principal(
    authorization: Optional[str] = Header(default=None),
    x_user: Optional[str] = Header(default=None),
    x_roles: Optional[str] = Header(default=None),
    x_tenant: Optional[str] = Header(default=None),
) -> Principal:
    requested_tenant = (x_tenant or "").strip().lower() or None

    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        try:
            if settings.auth_require_verified_jwt:
                payload = _decode_verified_jwt(token)
            elif settings.auth_allow_insecure_dev_tokens:
                payload = _decode_jwt_payload(token)
            else:
                raise ValueError("Insecure token parsing disabled")
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {exc}") from exc

        username = str(payload.get("preferred_username") or payload.get("sub") or "unknown-user")
        mapped_roles = _map_roles(_extract_roles(payload))
        if settings.auth_enforce_mapped_roles and not mapped_roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Token has no mapped platform roles")

        token_tenant = _extract_tenant_from_payload(payload)
        if token_tenant and requested_tenant and token_tenant != requested_tenant:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tenant header does not match token tenant")

        tenant = token_tenant or requested_tenant or settings.default_tenant_code
        return Principal(username=username, roles=mapped_roles or ["viewer"], tenant_code=tenant, token_payload=payload)

    if settings.auth_required:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization required")

    username = x_user or settings.auth_default_user
    if x_roles:
        raw_roles = [chunk.strip() for chunk in x_roles.split(",") if chunk.strip()]
    else:
        raw_roles = [chunk.strip() for chunk in settings.auth_default_roles.split(",") if chunk.strip()]

    roles = _map_roles(raw_roles)
    if settings.auth_enforce_mapped_roles and not roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No mapped platform roles for request")

    tenant = requested_tenant or settings.default_tenant_code

    return Principal(username=username, roles=roles, tenant_code=tenant, token_payload={})


def require_roles(*required_roles: str) -> Callable[[Principal], Principal]:
    required = {role.strip() for role in required_roles if role.strip()}

    def dependency(principal: Principal = Depends(get_current_principal)) -> Principal:
        if not required:
            return principal

        principal_roles = set(principal.roles)
        if principal_roles.intersection(required):
            return principal

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Missing required role. Need one of: {sorted(required)}",
        )

    return dependency
