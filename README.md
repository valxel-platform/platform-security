# Platform security

Identity and the service mesh for every Valxel product (constitution VX-17). This repo holds the
platform's half: the spec format, its checker, the realm generator and the mesh's install. Each
product holds its own half, its spec, in its own GitHub org (`<prefix>security/security.yaml`,
made from [template-security](https://github.com/valxel-platform/template-security)). See
`examples/security.yaml`.

| Layer | What | Where |
| --- | --- | --- |
| Identity | Keycloak (operator, HA, managed Postgres), **one realm per product**: the BFF and mobile clients (PKCE; mobile apps public, with bounded offline sessions), audiences for services and MCP servers, token exchange for services crossing trust boundaries and for agents, permissions as roles through groups, organizations as tenants | `keycloak/`, `python -m platform_security realm` |
| Service identity | **Istio ambient**: mutual TLS for every workload from its service account, alongside OpenChoreo's Cilium | `mesh/install/` |
| Who may call whom | Per environment namespace: mTLS STRICT, deny by default, allow only the spec's `calls`, ingress only to the BFF, the data plane's metrics collector (namespace `observability`) only to the management port (8081), where every template serves its metrics | Rendered by OpenChoreo: agentic-sdlc `platform/openchoreo/` (the `valxel` project type and the component types' `allowedCallers`) |

## How a request is trusted

1. A person signs in at the product's BFF (OIDC code + PKCE). The BFF keeps the tokens; the
   browser holds a `__Host-SESSION` cookie.
2. The BFF calls a service with the person's access token: `aud` holds the product's API audience.
   The mesh proves the BFF is the BFF (mTLS, `cluster.local/ns/<ns>/sa/<bff>`), and the policy
   allows only that call.
3. The service checks the token (issuer, keys, expiry, audience), the endpoint's permission (the
   token's `scope` and the person's `permissions` both include it) and the record (tenant from
   `organization`).
4. Inside the product, a service forwards the token; across a trust boundary (a shared service,
   another product, PHI stores, payments) it exchanges it at Keycloak for one issued only for the
   target. Agents always exchange, per MCP server, for the person behind each step.

## Use

```bash
pip install -e '.[dev]'
python -m platform_security check security.yaml
python -m platform_security realm security.yaml -o build/realm.json   # keycloak-config-cli
```

A product's security repo checks its spec on every pull request with a pinned release:

```yaml
jobs:
  check:
    uses: valxel-platform/platform-security/.github/workflows/check.yml@v0.2.0
    with: { version: v0.2.0 }
```

The checker holds the platform's rules a product can't opt out of: short-lived tokens, exact
redirect URIs, PKCE, declared scopes and roles, and calls that name real ports and never the
management port (8081).

## How the rules reach the clusters

1. At G4, the Valxel SDLC opens a pull request on the product's security repo adding the calls its
   approved design makes. The product's security owners review it (CODEOWNERS), and CI runs the
   checker.
2. On merge, the Valxel SDLC sets each component's `allowedCallers` (and the BFF's `fromIngress`)
   in OpenChoreo.
3. OpenChoreo renders the AuthorizationPolicies into each environment's namespace with the
   component's next release, so a new call reaches dev, staging and production with the code that
   makes it. Nobody runs `kubectl`, and nothing here holds cluster credentials.

Each product runs in its own clusters (`<product>-nonprod`, `<product>-prod`), so one product's
rules never reach another's. Dev and staging share the nonprod cluster, but every rule names the
caller in its own namespace, so the two can't call each other.

## License

MIT, see [LICENSE](LICENSE).
