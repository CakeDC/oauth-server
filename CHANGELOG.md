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
  authorization spec requires localhost or https redirect URIs); a host that enables it accepts any
  private-use scheme the matcher does not refuse. A client that uses a `cursor://`-style scheme is
  accepted only with `allowPrivateSchemes` enabled; the library makes no claim about what a particular
  third-party tool sends. At dynamic registration, a client that says `"application_type": "web"` can
  no longer register loopback `http` URIs, and a client that omits `application_type` is registered as
  `native` when none of its redirect URIs is https.
- New, optional extension point: `View\RedirectNoticeRendererInterface` with `View\RedirectNoticeView`,
  implemented by `HtmlErrorPageRenderer`. A custom `ErrorPageRendererInterface` that does not implement
  it shows its plain error page (no link) where the built-in one offers the link. New `Messages` keys
  `error.untrusted`, `error.continue` and `consent.approvedBefore`; new `ConsentView::$approvedBefore`;
  new `ConsentService::hasConsented()` and `ConsentService::identityIsAssured()`;
  `AuthorizationError` carries the `Client` (`$client`). The constructor defaults of `ClientRegistrar` and
  `ClientResolver` for private schemes are now `false`.
- Consent page identity: a name is chosen by the client, so it no longer names a self-registered
  client. The consent page and the connections page headline such a client by the host its answer goes
  to (like a metadata document client), never by its name or by a redirect URI it merely listed; when
  the answer goes to a private-use scheme (anyone can claim the scheme `claude.ai:`) the label is the
  fixed, translatable text "An application on this computer" (new `Messages` key `client.local`) and the
  scheme appears only as the destination. The declared name is shown only as a quoted `<q>` line
  ("It calls itself ...", `consent.declaredName`, which no longer contains quote characters), so a name
  cannot close the quote and speak for the server. Custom renderer authors: `client->name` and
  `ConsentView::clientHost()` of earlier code were spoofable for dynamic clients; use
  `ConsentView::clientLabel()` (empty for a private-use redirect, show a fixed text then) and
  `declaredName()`. `clientHost()` is now the host the answer goes to for a self-registered client.
  New `Client::hostLabel()` does the same for the connections page.
- Names: client names (dynamic registration, `ClientRegistrar::create()`) and personal token names
  must contain a letter, number, punctuation or symbol and reject control characters, line and paragraph
  separators, bidirectional controls and every other format character (`Cf`) except the soft hyphen,
  tag characters and U+200C/U+200D between two visible characters (Persian, Indic scripts, emoji
  sequences); also characters that draw nothing (U+034F, fillers, U+FFFC) and runs of more than four
  combining marks. A metadata document name that fails these checks falls back to the host of its
  `client_id`. Length limits count characters, not bytes. Names that look like host names stay
  accepted, because no page headlines a name.
- One host classification: new `Support\HostClass` covers loopback, unspecified (`0.0.0.0`, `::`) and
  `.localhost` hosts for the consent memory (`ConsentService::identityIsAssured()`) and the consent page,
  so `https://0.0.0.0/...` and `https://[::]/...` are no longer treated as assured and the "any program
  on this computer" warning always appears when "approved before" does. The redirect URI matcher still
  uses only the loopback literals of RFC 8252 and accepts the same URIs as before.
  `ConsentView::redirectHost()` now returns the scheme of a private-use URI, as
  `RedirectNoticeView::redirectHost()` does. `Client::redirectsOnlyToLoopback()` now also counts
  `.localhost` names, `127.0.0.0/8`, unspecified addresses and private-use schemes. New
  `ConsentView::clientLabel()` and `declaredName()`, `ClientMetadata::characterLength()`.
- Docs: `docs/users.md` teaches identifying a client by `clientId`, not by its name, and says an
  anonymous POST gets the error page, not the login.
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
