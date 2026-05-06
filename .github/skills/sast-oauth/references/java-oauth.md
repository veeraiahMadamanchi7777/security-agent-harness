# Java OAuth/OIDC Reference

## Review Targets

- Spring Security OAuth2 client/resource server.
- Custom OAuth callback controllers.
- Social login and SSO account linking.
- JWT bearer resource server config.
- Token relay to downstream services.

## Required Controls

- Exact redirect URI allowlist.
- High-entropy `state` tied to browser session.
- OIDC `nonce` validation where applicable.
- PKCE for public clients and mobile/SPA flows.
- Issuer, audience, expiration, signature, and algorithm validation.
- Stable provider subject for account linking; do not rely on unverified email alone.
