# Changelog

## 1.0.0-beta1 (unreleased)

First release.

- Storage contract: saving a code or a token whose id already exists throws and leaves the stored row
  unchanged (`InMemoryStorage` used to overwrite it).
- OAuth 2.1 authorization server library for PHP 8.2 and newer, built on PSR-7, PSR-15, PSR-14,
  PSR-16, PSR-17, PSR-20 and PSR-3.
- Authorization code flow with mandatory PKCE (S256), exact redirect URI matching and loopback
  redirects on any port (RFC 8252).
- Refresh tokens with rotation, reuse detection that revokes the token family, a configurable grace
  window for lost responses and a hard family lifetime.
- Client credentials grant.
- Client ID Metadata Documents with SSRF protection (pinned connection, address checks, no redirects,
  size and time limits) and stale-if-error caching.
- Dynamic client registration (RFC 7591) in `open`, `token` and `closed` modes, and clients registered
  by hand with `ClientRegistrar::create()`.
- Resource indicators (RFC 8707), the `iss` authorization response parameter (RFC 9207) and
  authorization server metadata (RFC 8414).
- Token revocation (RFC 7009) and introspection (RFC 7662).
- Consent page and connections page, with replaceable renderers and translatable texts (`Messages`).
- Personal access tokens.
- Scopes and scope hierarchies, checked on every request.
- `PdoStorage` for SQLite, MySQL/MariaDB and PostgreSQL, `InMemoryStorage` and
  `StorageContractTestCase` for custom storages.
- `BearerTokenMiddleware` for PSR-15 stacks and a bridge for the official MCP PHP SDK
  (`AuthorizationServer::mcpTokenValidator()`).
- PSR-14 events: `TokenIssued`, `TokenRevoked`, `ConsentGranted`, `ClientRegistered`,
  `RefreshTokenReused` and `AuthorizationDenied`.
- Rate limiting through any PSR-16 cache, and a `Pruner` for housekeeping.
- A standalone example in `examples/standalone/` and a run of the official MCP conformance suite for
  authorization servers (`tests/Conformance/run.sh`).
- Documentation in `docs/`.
- `@internal`: `ClientResolver`, `ClientAuthenticator`, `CodeIssuer`, `TokenIssuer` and
  `RefreshTokenRotator` are internal classes that may change in any 1.x release. The constructors of the
  other service, handler and view classes (`TokenRevoker`, `ClientRegistrar`, `TokenValidator`, the HTTP
  handlers, `ConsentService`, `ConnectionService`, `AuthorizationRequestValidator`,
  `MetadataDocumentFetcher`, `ConsentView`, `ConnectionsView`) are internal: build them through
  `AuthorizationServer`. Their documented methods and properties follow semantic versioning.
- Schema changes after 1.0.0 ship as SQL files under `schema/upgrades/`; see `docs/storage.md`.
