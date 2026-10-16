# Changelog

## 1.0.0-beta1 (unreleased)

First release.

- Storage contract: saving a code or a token whose id already exists throws and leaves the stored row
  unchanged (`InMemoryStorage` used to overwrite it).
- `/authorize` is no longer an open redirector (RFC 9700 section 4.11.2): a redirectable error is never
  sent before the person is authenticated (an anonymous GET gets `loginResponse()` with the same return
  URL and is validated again after the login; an anonymous POST gets the error page), and it is
  redirected automatically only to a trusted redirect URI: a client registered with
  `ClientRegistrar::create()`, or one the signed-in person approved before (any resource). Dynamic and
  metadata document clients without such a consent get the error page naming the destination host,
  with a "Continue to" link. "Deny" on the consent page still redirects with `access_denied`.
- A remembered consent skips the consent page only when the client's identity is assured (RFC 8252
  section 8.6): a confidential client, or an `https` redirect URI on a host that is not this computer.
  Public loopback and private-scheme clients (Claude Code among them) see the page on every new
  connection, with a line saying they were approved before.
- Redirect URI policy: `registration.allowPrivateSchemes` now defaults to `false` (the MCP
  authorization spec requires localhost or https redirect URIs); when enabled, a private-use scheme must
  be a reverse domain name with a dot (RFC 8252 section 7.1), also for `ClientRegistrar::create()` and
  metadata documents. A dynamically registered `web` client can no longer register loopback `http`
  URIs; it must send `"application_type": "native"`.
- New, optional extension point: `View\RedirectNoticeRendererInterface` with `View\RedirectNoticeView`,
  implemented by `HtmlErrorPageRenderer`. A custom `ErrorPageRendererInterface` that does not implement
  it shows its plain error page (no link) where the built-in one offers the link. New `Messages` keys
  `error.untrusted`, `error.continue` and `consent.approvedBefore`; new `ConsentView::$approvedBefore`;
  new `ConsentService::hasConsented()` and `ConsentService::identityIsAssured()`;
  `AuthorizationError` carries the `Client` (`$client`); new
  `RedirectUriMatcher::dynamicRegistrationError()`. The constructor defaults of `ClientRegistrar` and
  `ClientResolver` for private schemes are now `false`.
- Standalone example: `setup.php` no longer records a consent, and `OAUTH_EXAMPLE_AUTO_APPROVE=1`
  (unsafe, used only by `tests/Conformance/run.sh`) answers the consent page with "Allow".
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
