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
  On the connections page a self-registered client is labelled by the hosts of its registered redirect
  URIs (new `Client::webHosts()` and `hasNonWebRedirect()`), plus "and an application on this computer"
  (`connections.hostsAndLocal`) when it also has a private-use redirect URI, or just the fixed text when
  it has none other.
- Names: client names (dynamic registration, `ClientRegistrar::create()`) and personal token names
  must contain a letter, number, punctuation or symbol and reject control characters, line and paragraph
  separators, bidirectional controls and every other format character (`Cf`) except the soft hyphen,
  tag characters only inside an emoji tag sequence (subdivision flags) and U+200C/U+200D between two
  visible characters (Persian, Indic scripts, emoji sequences); also characters that draw nothing
  (U+034F, fillers, U+FFFC, unassigned default-ignorable code points) and runs of more than four
  combining marks (format characters do not break a run). A metadata document name that fails these checks falls back to the host of its
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
- Refresh scopes (RFC 6749 section 6, OAuth 2.1 section 4.3.3): a refresh keeps the presented refresh
  token's scopes on the new refresh token, minus scopes the resource no longer declares. A requested
  `scope`, the client's registered scopes and the owner's current `scopesFor()` narrow only the new access
  token, so a down-scoped refresh can ask for the wider scope again next time and a person demoted, then
  promoted, gets the scopes back at the next refresh. The response's `scope` still describes the access
  token. (This replaces the earlier rule that stored the narrowed, minimal set on the refresh token.)
  `TokenIssuer::issue()` (internal) takes an optional trailing `$refreshScopes`.
- Tests now pin that a refresh token with real scopes is refused as a bearer token ("The access token is
  invalid.") by `TokenValidator`, `BearerTokenMiddleware` and the MCP bridge; removing the type check
  fails them.
- Revocation reaches pending codes: `TokenRevoker::revokeAllForSubject()` (for people), revoking a
  connection (`ConnectionService::revokeConnection()`, the connections page) and
  `TokenRevoker::revokeAllForClient()` delete the authorization codes that were not exchanged yet, so a
  code issued just before can no longer open a new family. Codes are deleted before tokens are revoked, so
  an exchange in flight either fails or has its tokens revoked. Exchanged codes are kept for replay
  detection. `revokeAllForSubject()` with `SubjectType::Client` deletes no codes (codes belong to people).
  The internal constructors of `TokenRevoker` (new second argument) and `ConnectionService` (new fourth
  argument) take the `AuthorizationCodeRepositoryInterface`.
- Storage interface additions (every storage must implement them; `InMemoryStorage` and `PdoStorage` do,
  and `StorageContractTestCase` covers them):
  `AuthorizationCodeRepositoryInterface::deleteCodesBySubject(string $subject, ?string $clientInternalId = null): int`
  and `AuthorizationCodeRepositoryInterface::deleteCodesByClient(string $clientInternalId): int`. Both delete
  only unused codes (expired or not) in one statement and return how many.
- Storage contract: `saveClient()` with a `client_id` that belongs to another row (another internal id)
  must throw a `RuntimeException` and leave both rows unchanged. `InMemoryStorage` used to keep two rows.
  The contract also re-saves a consent under its own id. `StorageContractTestCase::makeCode()` takes an
  optional `$subject`. `docs/storage.md` now states that atomic rules need one conditional statement or
  an upsert, which a sequential contract cannot prove.
- `PdoStorage::saveConsent()` is one upsert (`ON CONFLICT ... DO UPDATE` on SQLite and PostgreSQL,
  `ON DUPLICATE KEY UPDATE` on MySQL and MariaDB): two concurrent first consents (a double click on
  "Allow") no longer make one request fail with a unique-key error; the second updates the first.
- `PdoStorage::prune()` claims each candidate client with one conditional `UPDATE` inside its transaction
  (after locking the row on MySQL and PostgreSQL) and deletes it only when the claim succeeds, so a client
  that a request used, or gave a live token, after it was selected is kept and its new token is not
  cascaded away.
- Schema: `oauth_authorization_codes` gains an index on `subject` (`oauth_authorization_codes_subject`).
  Beta databases created earlier work without it; recreate the tables or add the index.
- Client ID Metadata Documents: a temporary fetch failure (network error, timeout, HTTP 5xx or 429) is no
  longer remembered as a rejection for 60 seconds (the CIMD draft forbids caching error responses), so a
  new client works as soon as its host is back. It is remembered only while a stored copy of the client is
  served instead (stale-if-error). Definite rejections are still remembered for 60 seconds.
- Docs: how to undo a metadata document client revocation with SQL, and `cimd.allowedHosts` as the
  reversible switch (`docs/operations.md`); the refresh grace window absorbs a lost response, not
  concurrent refreshes (`docs/security.md`).
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

### Known issues

- Concurrent refreshes with the same refresh token can revoke the whole family: one request wins, the
  others get `invalid_grant` and the reuse detection fires a false `RefreshTokenReused`. The grace window
  does not absorb concurrent refreshes (only a retry after a lost response). Not fixed in this beta; it is
  being observed with claude.ai, and if real clients refresh in parallel a later beta will answer
  concurrent callers inside the grace window with the winner's response. Clients must send one refresh at
  a time per token. See `docs/security.md`.
