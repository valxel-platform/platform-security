# Platform security

Identity and the service mesh for every Vrixel product (constitution VX-17), generated from one
spec per product (`products/<product>.yaml`):

| Layer | What | Where |
| --- | --- | --- |
| Identity | Keycloak (operator, HA, managed Postgres), **one realm per product**: the BFF and mobile clients (PKCE; mobile apps public, with bounded offline sessions), audiences for services and MCP servers, token exchange for services crossing trust boundaries and for agents, permissions as roles through groups, organizations as tenants | `keycloak/`, `python -m platform_security realm` |
| Service identity | **Istio ambient**: mutual TLS for every workload from its service account, alongside OpenChoreo's Cilium | `mesh/install/` |
| Who may call whom | Per product namespace: mTLS STRICT, deny by default, allow only the declared calls (mirrors `workload.yaml` dependencies), ingress only to the BFF, monitoring only to the management port | `python -m platform_security mesh` |

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
python -m platform_security check products/<product>.yaml
python -m platform_security realm products/<product>.yaml -o build/<product>-realm.json   # keycloak-config-cli
python -m platform_security mesh  products/<product>.yaml -o build/<product>-mesh.yaml    # kubectl apply / GitOps
```

The Vrixel SDLC adds clients and calls to a product's spec when a design (G4) adds a component or
a dependency; this repo's pull requests are reviewed by the platform's security owners.
