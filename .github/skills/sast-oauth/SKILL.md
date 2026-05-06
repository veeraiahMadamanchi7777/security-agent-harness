---
name: sast-oauth
description: Review OAuth2 and OpenID Connect flows for redirect URI, state, PKCE, token validation, and account-linking flaws.
---

# SKILL: sast-oauth — OAuth and OIDC Flow Review

## Purpose

Find OAuth/OIDC implementation flaws that lead to account takeover, token leakage, login CSRF, authorization code interception, or confused-deputy bugs.

Load [`references/java-oauth.md`](references/java-oauth.md).

## Method

1. Identify OAuth clients, authorization servers, OIDC resource servers, social login, SSO, and token exchange code.
2. Review authorization request construction: redirect URI, state, nonce, PKCE, scopes, prompt, and response mode.
3. Review callback handling: state and nonce validation, redirect target, code exchange, token storage, and account linking.
4. Review JWT/OIDC token validation: issuer, audience, signature algorithm, expiration, nonce, `azp`, and key selection.

## Searches

```bash
rg -n "OAuth2|Oidc|ClientRegistration|OAuth2AuthorizedClient|authorizationUri|redirectUri|state|nonce|PKCE|code_verifier|JwtDecoder|NimbusJwtDecoder|issuer-uri|jwk-set-uri" --glob "*.java" --glob "*.yml" --glob "*.properties"
```

## True Positive Signals

- Missing or non-random `state` in browser OAuth flows.
- Missing OIDC `nonce` validation for implicit/hybrid flows.
- Redirect URI derived from user-controlled `returnUrl`, `next`, or headers.
- Authorization code flow for public clients lacks PKCE.
- ID token accepted without issuer, audience, signature, or expiration validation.
- Account linking trusts unverified email or provider-controlled mutable identifiers.

## Output

Include flow, actor, missing OAuth control, token or account impact, and framework-specific remediation.
