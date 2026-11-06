"""A product's Keycloak realm, as a realm representation (Keycloak's import format, also what
keycloak-config-cli applies continuously).

- **Audience**: every token for the product's API carries `aud: <audience>` (services check it),
  plus the services and agents that exchange tokens (Keycloak's standard token exchange only lets
  a client exchange tokens issued for it).
- **Permissions**: realm roles named like the scopes (`greetings:write`), given to people through
  groups (`admin`). Tokens carry both what the app asked for (`scope`) and what the person holds
  (`permissions`); services grant a permission only when both say so.
- **Tenants**: Keycloak organizations; tokens carry `organization`.
- **Clients**: the BFF (confidential, PKCE), mobile apps (public, PKCE), services and MCP servers
  (audiences), services and agents that exchange tokens (confidential, standard token exchange,
  private_key_jwt), agents (also client credentials, for tool metadata only).
- **Sessions**: short access tokens, rotating refresh tokens, brute-force protection, events on.
"""

from __future__ import annotations

from typing import Any

OIDC = "openid-connect"


def audience_mapper(name: str, client: str = "", custom: str = "") -> dict[str, Any]:
    config = {"access.token.claim": "true", "id.token.claim": "false", "introspection.token.claim": "true"}
    if client:
        config["included.client.audience"] = client
    else:
        config["included.custom.audience"] = custom
    return {"name": name, "protocol": OIDC, "protocolMapper": "oidc-audience-mapper", "config": config}


def scope(name: str, *, in_token: bool, mappers: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "name": name,
        "protocol": OIDC,
        "attributes": {"include.in.token.scope": str(in_token).lower(), "display.on.consent.screen": "false"},
        "protocolMappers": mappers or [],
    }


def confidential(client_id: str, **extra: Any) -> dict[str, Any]:
    base = {
        "clientId": client_id,
        "protocol": OIDC,
        "enabled": True,
        "publicClient": False,
        "standardFlowEnabled": False,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "frontchannelLogout": False,
        "fullScopeAllowed": False,
        "attributes": {},
    }
    base.update(extra)
    return base


def exchanger(client_id: str, optional: list[str], service_account: bool = False) -> dict[str, Any]:
    """A client that exchanges tokens: authenticates with a signed JWT (its key registered at deploy)."""
    return confidential(
        client_id,
        clientAuthenticatorType="client-jwt",
        serviceAccountsEnabled=service_account,
        attributes={
            "standard.token.exchange.enabled": "true",
            "token.endpoint.auth.signing.alg": "RS256",
            "use.jwks.url": "false",
            # The public certificate of the client's key, from the deploy environment.
            "jwt.credential.certificate": f"$(env:{env_name(client_id)}_CERTIFICATE)",
        },
        defaultClientScopes=["basic"],
        optionalClientScopes=optional,
    )


def env_name(client_id: str) -> str:
    return client_id.upper().replace("-", "_")


def render(spec: dict[str, Any]) -> dict[str, Any]:
    product, domain, audience = spec["product"], spec["domain"], spec["audience"]
    lifetime = int(spec.get("token_lifetime_seconds", 300))
    perms = sorted((spec.get("scopes") or {}).keys())
    services = spec.get("services") or []
    agents = spec.get("agents") or []
    bff = spec["bff"]["client_id"]

    # Who must be in the user token's audience: the product's API, and every client that exchanges it.
    exchanging = [s["name"] for s in services if s.get("exchanges")] + [a["name"] for a in agents]
    product_scope = scope(
        audience,
        in_token=False,
        mappers=[audience_mapper(f"aud-{audience}", custom=audience)]
        + [audience_mapper(f"aud-{c}", client=c) for c in exchanging]
        + [
            {
                "name": "permissions",
                "protocol": OIDC,
                "protocolMapper": "oidc-usermodel-realm-role-mapper",
                "config": {
                    "claim.name": "permissions",
                    "multivalued": "true",
                    "jsonType.label": "String",
                    "access.token.claim": "true",
                    "id.token.claim": "false",
                    "introspection.token.claim": "true",
                },
            }
        ],
    )
    scopes = [product_scope] + [scope(p, in_token=True) for p in perms]

    # Audience scopes for exchange targets, offered only to the clients allowed to request them.
    targets: dict[str, dict[str, Any]] = {}

    def target(aud: str) -> str:
        name = f"to-{aud}"
        targets.setdefault(name, scope(name, in_token=False, mappers=[audience_mapper(f"aud-{aud}", client=aud)]))
        return name

    user_scopes = ["basic", "profile", "organization", audience, *perms]
    clients = [
        confidential(
            bff,
            standardFlowEnabled=True,
            clientAuthenticatorType="client-secret",
            redirectUris=[f"https://{domain}/login/oauth2/code/keycloak"],
            webOrigins=[f"https://{domain}"],
            attributes={
                "pkce.code.challenge.method": "S256",
                "post.logout.redirect.uris": f"https://{domain}/",
                "use.refresh.tokens": "true",
                "client_credentials.use_refresh_token": "false",
            },
            defaultClientScopes=user_scopes,
            optionalClientScopes=[],
        )
    ]
    for m in spec.get("mobile") or []:
        clients.append(
            {
                **confidential(m["client_id"], standardFlowEnabled=True, publicClient=True),
                "redirectUris": list(m["redirect_uris"]),
                "attributes": {"pkce.code.challenge.method": "S256", "use.refresh.tokens": "true"},
                "defaultClientScopes": user_scopes,
            }
        )
    for s in services:
        if s.get("exchanges"):
            clients.append(
                exchanger(
                    s["name"],
                    [target(x["audience"]) for x in s["exchanges"]]
                    + sorted({p for x in s["exchanges"] for p in x.get("scope", "").split() if p in perms}),
                )
            )
        else:
            clients.append(confidential(s["name"], bearerOnly=True))  # an audience, never a caller
    for a in agents:
        clients.append(
            exchanger(a["name"], [target(m["audience"]) for m in a.get("mcp_servers") or []], service_account=True)
        )
    for m in spec.get("mcp_servers") or []:
        clients.append(confidential(m["name"], bearerOnly=True))

    groups = [
        {
            "name": role,
            "path": f"/{role}",
            "realmRoles": sorted(p for p, granted in (spec.get("scopes") or {}).items() if role in (granted or [])),
        }
        for role in spec.get("roles") or []
    ]
    return {
        "realm": product,
        "enabled": True,
        "sslRequired": "external",
        "defaultSignatureAlgorithm": "RS256",
        "accessTokenLifespan": lifetime,
        "ssoSessionIdleTimeout": 1800,
        "ssoSessionMaxLifespan": 36000,
        "revokeRefreshToken": True,
        "refreshTokenMaxReuse": 0,
        "bruteForceProtected": True,
        "failureFactor": 5,
        "passwordPolicy": "length(12) and notUsername and notEmail and passwordHistory(5)",
        "organizationsEnabled": True,
        "eventsEnabled": True,
        "adminEventsEnabled": True,
        "adminEventsDetailsEnabled": False,  # never store request bodies
        "roles": {"realm": [{"name": p, "description": f"Permission {p}"} for p in perms]},
        "groups": groups,
        "clientScopes": scopes + list(targets.values()),
        "clients": clients,
    }
