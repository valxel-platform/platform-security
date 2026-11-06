# Keycloak

1. Install the operator (version matching `keycloak.yaml`'s image) into namespace `keycloak`.
2. Create the database secret (`keycloak-db`) and TLS secret (`keycloak-tls`), then apply
   `keycloak.yaml`.
3. For each product, generate its realm and apply it with
   [keycloak-config-cli](https://github.com/adorsys/keycloak-config-cli), which keeps the realm in
   line with the file on every run (the operator's `KeycloakRealmImport` only creates a realm once):

   ```bash
   python -m platform_security realm products/emr.yaml -o build/emr-realm.json
   # in CI/CD, with the clients' public certificates as environment variables:
   #   EMR_INTAKE_AGENT_CERTIFICATE=...  (one per client that exchanges tokens)
   keycloak-config-cli --import.files.locations=build/emr-realm.json \
     --import.var-substitution.enabled=true --keycloak.url=https://id.vrixel.com ...
   ```

## Signing keys

Each realm signs tokens with RS256. Start with Keycloak's generated keys; for PHI and payments
products, import keys generated in AWS KMS or an HSM as an `rsa` key provider. To rotate: add the
new key with a higher priority (it signs from then on), keep the old one *passive* (still in the
JWKS, so tokens it signed keep verifying), and disable it once those tokens have expired
(`token_lifetime_seconds`, plus refresh token lifetime for sessions).

## Clients that exchange tokens

Services crossing a trust boundary and agents authenticate with `private_key_jwt`: each holds its
private key (a Kubernetes secret from AWS Secrets Manager via External Secrets), and the realm holds
only the public certificate (`<CLIENT>_CERTIFICATE`). No shared secrets on the wire.

## Shared services

Standard token exchange works within one realm. A shared service used by several products has an
audience client in **each** product's realm, and accepts each of those realms as an issuer.
