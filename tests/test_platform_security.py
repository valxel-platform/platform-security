from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
import yaml

from platform_security import __main__ as cli
from platform_security import mesh, realm, spec

EXAMPLE = Path(__file__).resolve().parents[1] / "products" / "example.yaml"


@pytest.fixture
def s() -> dict:
    return spec.load(EXAMPLE)


def by_id(r: dict) -> dict:
    return {c["clientId"]: c for c in r["clients"]}


def test_the_bff_signs_in_with_pkce_and_exact_redirects(s: dict) -> None:
    bff = by_id(realm.render(s))["example-bff"]
    assert bff["publicClient"] is False and bff["standardFlowEnabled"] is True
    assert bff["directAccessGrantsEnabled"] is False and bff["implicitFlowEnabled"] is False
    assert bff["attributes"]["pkce.code.challenge.method"] == "S256"
    assert bff["redirectUris"] == ["https://example.vrixel.com/login/oauth2/code/keycloak"]
    assert {"example-api", "organization", "greetings:read", "greetings:write"} <= set(bff["defaultClientScopes"])
    assert bff["fullScopeAllowed"] is False


def test_tokens_carry_the_product_audience_and_the_exchangers(s: dict) -> None:
    r = realm.render(s)
    product = next(c for c in r["clientScopes"] if c["name"] == "example-api")
    auds = {
        m["config"].get("included.custom.audience") or m["config"].get("included.client.audience")
        for m in product["protocolMappers"]
        if m["protocolMapper"] == "oidc-audience-mapper"
    }
    assert auds == {"example-api", "example-agent"}  # the agent exchanges people's tokens
    perms = next(m for m in product["protocolMappers"] if m["name"] == "permissions")
    assert perms["config"]["claim.name"] == "permissions"


def test_permissions_are_roles_given_through_groups(s: dict) -> None:
    r = realm.render(s)
    assert [x["name"] for x in r["roles"]["realm"]] == ["greetings:read", "greetings:write"]
    assert {g["name"]: g["realmRoles"] for g in r["groups"]} == {
        "member": ["greetings:read"],
        "admin": ["greetings:read", "greetings:write"],
    }


def test_agents_exchange_for_their_mcp_servers_only(s: dict) -> None:
    clients = by_id(realm.render(s))
    agent = clients["example-agent"]
    assert agent["attributes"]["standard.token.exchange.enabled"] == "true"
    assert agent["clientAuthenticatorType"] == "client-jwt"  # private_key_jwt, no shared secret
    assert agent["attributes"]["jwt.credential.certificate"] == "$(env:EXAMPLE_AGENT_CERTIFICATE)"
    assert agent["serviceAccountsEnabled"] is True  # tool metadata only
    assert agent["optionalClientScopes"] == ["to-example-care-mcp"]
    assert clients["example-care-mcp"]["bearerOnly"] is True
    assert clients["example-service"]["bearerOnly"] is True  # forwards inside the product: no exchange


def test_services_that_cross_a_trust_boundary_can_exchange(s: dict) -> None:
    s2 = copy.deepcopy(s)
    s2["services"][0]["exchanges"] = [{"audience": "ss-consent-api", "scope": "greetings:read"}]
    r = realm.render(s2)
    svc = by_id(r)["example-service"]
    assert svc["attributes"]["standard.token.exchange.enabled"] == "true"
    assert svc["optionalClientScopes"] == ["to-ss-consent-api", "greetings:read"]
    product = next(c for c in r["clientScopes"] if c["name"] == "example-api")
    assert any(m["config"].get("included.client.audience") == "example-service" for m in product["protocolMappers"])


def test_sessions_are_short_and_refresh_tokens_rotate(s: dict) -> None:
    r = realm.render(s)
    assert r["accessTokenLifespan"] == 300 and r["revokeRefreshToken"] is True and r["refreshTokenMaxReuse"] == 0
    assert r["bruteForceProtected"] is True and r["sslRequired"] == "external" and r["organizationsEnabled"] is True
    assert r["adminEventsDetailsEnabled"] is False


def test_mobile_apps_are_public_clients_with_pkce(s: dict) -> None:
    s2 = copy.deepcopy(s)
    s2["mobile"] = [{"client_id": "example-mobile", "redirect_uris": ["com.vrixel.example:/callback"]}]
    r = realm.render(s2)
    m = by_id(r)["example-mobile"]
    assert m["publicClient"] is True and m["attributes"]["pkce.code.challenge.method"] == "S256"
    assert m["attributes"]["post.logout.redirect.uris"] == "com.vrixel.example:/callback"
    assert m["optionalClientScopes"] == ["offline_access"] and "example-api" in m["defaultClientScopes"]
    assert r["offlineSessionIdleTimeout"] == 7 * 86400 and r["offlineSessionMaxLifespan"] == 30 * 86400
    s2["mobile"][0]["redirect_uris"] = ["https://*.example.com/*"]
    assert any("exact" in p for p in spec.check(s2))
    s2["mobile"][0]["redirect_uris"] = ["http://localhost/callback"]
    assert any("plain http" in p for p in spec.check(s2))
    s2["mobile"][0]["redirect_uris"] = []
    assert any("redirect_uris are required" in p for p in spec.check(s2))
    s2["offline_sessions"] = {"idle_days": 40, "max_days": 30}
    assert any("offline_sessions" in p for p in spec.check(s2))


def test_the_mesh_denies_by_default_and_allows_declared_calls(s: dict) -> None:
    docs = mesh.render(s)
    kinds = {(d["kind"], d["metadata"]["name"]) for d in docs}
    assert ("PeerAuthentication", "strict-mtls") in kinds
    nothing = next(d for d in docs if d["metadata"]["name"] == "allow-nothing")
    assert nothing["spec"] == {}
    ns = next(d for d in docs if d["kind"] == "Namespace")
    assert ns["metadata"]["labels"]["istio.io/dataplane-mode"] == "ambient"
    call = next(d for d in docs if d["metadata"]["name"] == "example-bff-to-example-service")
    assert call["spec"]["selector"]["matchLabels"] == {"app.kubernetes.io/name": "example-service"}
    assert call["spec"]["rules"][0]["from"][0]["source"]["principals"] == ["cluster.local/ns/example/sa/example-bff"]
    assert call["spec"]["rules"][0]["to"][0]["operation"]["ports"] == ["8080"]
    ingress = next(d for d in docs if d["metadata"]["name"] == "ingress-to-example-bff")
    assert ingress["spec"]["rules"][0]["from"][0]["source"]["namespaces"] == ["openchoreo-data-plane"]
    assert yaml.safe_load_all(mesh.dump(docs))


def test_specs_are_checked(s: dict) -> None:
    assert spec.check(s) == []
    bad = {
        **s,
        "product": "Bad Name",
        "token_lifetime_seconds": 3600,
        "scopes": {"Greetings": ["ghost"]},
        "calls": [{"from": "a"}],
        "bff": {},
    }
    problems = spec.check(bad)
    assert any("lowercase" in p for p in problems)
    assert any("60-900" in p for p in problems)
    assert any("greetings:read" in p for p in problems)
    assert any("unknown roles" in p for p in problems)
    assert any("from, to and port" in p for p in problems)
    assert any("bff.client_id" in p for p in problems)
    dup = copy.deepcopy(s)
    dup["mcp_servers"].append({"name": "example-service"})
    assert any("names used twice" in p for p in spec.check(dup))
    assert "domain is required" in spec.check({})


def test_the_cli_renders_both(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "realm.json"
    assert cli.main(["realm", str(EXAMPLE), "-o", str(out)]) == 0
    assert json.loads(out.read_text())["realm"] == "example"
    assert cli.main(["mesh", str(EXAMPLE)]) == 0
    assert "AuthorizationPolicy" in capsys.readouterr().out
    assert cli.main(["check", str(EXAMPLE)]) == 0
    bad = tmp_path / "bad.yaml"
    bad.write_text("product: x\n")
    assert cli.main(["check", str(bad)]) == 1
