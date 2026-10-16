# Changelog

## 1.0.0-beta1 (unreleased)

First release.

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
- `@internal`: `ClientResolver`, `ClientAuthenticator`, `CodeIssuer`, `TokenIssuer`,
  `RefreshTokenRotator`, `AuthorizationRequestValidator`, `ScopeResolver`, `RateLimit\RateLimiter`,
  `Http\HttpResponder`, `Http\Params`, `Http\FormBody`, `Http\RequestPath`, `Http\BasicCredentials`,
  `Http\Handler\GuardsErrors`, `View\Html\Html`, `Grant\AuthorizationRequest`, `Grant\AuthorizationError`,
  `Grant\RedirectUrl`, `Client\ClientMetadata`, `Bridge\McpSdk\SdkRequirement` and every class in
  `Support\` (`Base64Url`, `HostName`, `HostClass`, `Time`, `Uuid`) are internal classes that may change
  in any 1.x release. So are the `AuthorizationServer` getters that return them: `responder()`,
  `scopeResolver()`, `clientResolver()`, `clientAuthenticator()`, `authorizationRequestValidator()`,
  `codeIssuer()`, `tokenIssuer()`, `refreshTokenRotator()` and `rateLimiter()`. The constructors of the
  other service, handler and view classes (`TokenRevoker`, `ClientRegistrar`, `TokenValidator`, the HTTP
  handlers, `BearerTokenMiddleware`, the MCP bridge `Bridge\McpSdk\TokenValidator`, `ConsentService`,
  `ConnectionService`, `MetadataDocumentFetcher`, `ConsentView`, `ConnectionsView`) are internal: build
  them through `AuthorizationServer`. Their documented methods and properties follow semantic
  versioning. `Http\ClientIp` stays public (it is the documented default of the `$clientIp` closure).
- Schema changes after 1.0.0 ship as SQL files under `schema/upgrades/`; see `docs/storage.md`.

### Changes since the first review

The release was reviewed before it was tagged. These entries describe what changed against earlier,
unreleased commits. They matter to code built against such a commit (a custom renderer or storage, the
CakePHP plugin) and to a database created from one.

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
  the tag characters of the flags of England, Scotland and Wales and U+200C/U+200D between two
  visible characters (Persian, Indic scripts, emoji sequences); also characters that draw nothing
  (U+034F, fillers, U+FFFC, unassigned default-ignorable code points) and runs of more than four
  combining marks (format characters do not break a run). A metadata document name that fails these
  checks falls back to the host of its `client_id`. Length limits count characters, not bytes. Names
  that look like host names stay accepted, because no page headlines a name.
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
  code issued just before can no longer open a new family. For a person and for a client, codes are
  deleted before tokens are revoked, so an exchange in flight either fails or has its tokens revoked. A
  connection revocation revokes the family first and deletes the codes after, so a code exchanged in
  between opens a new family, which the connections page lists and the person can revoke. Exchanged codes
  are kept for replay detection. `revokeAllForSubject()` with `SubjectType::Client` deletes no codes
  (codes belong to people). The internal constructors of `TokenRevoker` (new second argument) and
  `ConnectionService` (new fourth argument) take the `AuthorizationCodeRepositoryInterface`.
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
- `ConsentRepositoryInterface::saveConsent()`: tolerating two racing first saves (the second replaces the
  scopes of the first instead of failing) is a requirement of the interface for every storage, not a
  property of `PdoStorage` alone. A storage of your own needs an upsert or an insert that falls back to
  an update on the unique key; the sequential contract cannot detect a storage that fails here.
- `PdoStorage::saveConsent()` is one upsert (`ON CONFLICT ... DO UPDATE` on SQLite and PostgreSQL,
  `ON DUPLICATE KEY UPDATE` on MySQL and MariaDB): two concurrent first consents (a double click on
  "Allow") no longer make one request fail with a unique-key error; the second updates the first.
- `PdoStorage::prune()` claims each candidate client with one conditional `UPDATE` inside its transaction
  (after locking the row on MySQL and PostgreSQL) and deletes it only when the claim succeeds, so a client
  that a request used, or gave a live token, after it was selected is kept and its new token is not
  cascaded away. `PruneLockTest` replays the race with two processes (a token insert held open while
  `prune()` runs) on PostgreSQL and MySQL/MariaDB when their DSNs are set; on PostgreSQL it fails without
  the row lock. `docs/storage.md` says which races the tests replay and which they do not.
- Schema: `oauth_authorization_codes` gains an index on `subject` (`oauth_authorization_codes_subject`).
  Beta databases created earlier work without it; recreate the tables or add the index. On SQLite and
  PostgreSQL `PdoStorage::createTables()` adds it. On MySQL and MariaDB the index sits inside
  `CREATE TABLE IF NOT EXISTS`, which skips an existing table, so add it by hand (`docs/storage.md`):
  `CREATE INDEX oauth_authorization_codes_subject ON oauth_authorization_codes (subject);`
- Client ID Metadata Documents: a temporary fetch failure (network error, timeout, HTTP 5xx or 429) is no
  longer remembered as a rejection for 60 seconds (the CIMD draft forbids caching error responses), so a
  new client works as soon as its host is back. It is remembered only while a stored copy of the client is
  served instead (stale-if-error). Definite rejections are still remembered for 60 seconds.
- Docs: how to undo a metadata document client revocation with SQL, and `cimd.allowedHosts` as the
  reversible switch (`docs/operations.md`); the refresh grace window absorbs a lost response, not
  concurrent refreshes (`docs/security.md`).
- `@internal` and the CakePHP plugin: the plugin uses `Support\Time` in `OrmStorage` and
  `new HttpResponder()` to read the core's page CSP; both still work but are now internal, so the plugin
  should stop depending on them.
- Error descriptions follow RFC 6749 sections 4.1.2.1 and 5.2 and RFC 6750 section 3: only %x20-21 /
  %x23-5B / %x5D-7E (printable ASCII without `"` and `\`), in JSON bodies, redirects and
  `WWW-Authenticate`. Messages now quote parameter names with `'` (`'code_verifier' is missing.`,
  `'code_challenge' is required (PKCE with S256).`, `application_type must be 'web' or 'native'.`), and a
  value copied from the request (a grant type, a scope, a repeated parameter's name, a host) has every
  other character replaced by `?` and is cut to 64 characters (`'a?b' is not a valid scope.`). The
  `OAuthException` and `ValidationFailure` constructors throw an `InvalidArgumentException` for any other
  description. New `OAuthException::isValidDescription()` (public) and `OAuthException::printable()`
  (internal). A failure remembered in the cache with a description from an older version is ignored.
- MCP bridge: `mcpTokenValidator()` and the bridge's constructor throw a `LogicException` that names
  the minimum, `mcp/sdk 0.9 or newer`, when `Mcp\Server\Authorization\AccessToken` does not exist
  (mcp/sdk 0.8 built the bridge and then failed with a `TypeError` on every valid token). Verified against
  the code of mcp/sdk 0.8.1. `docs/mcp.md`, `docs/installation.md` and the `suggest` entry state the
  minimum. No 0.8 compatibility layer.
- Rate limiting fails open: when the PSR-16 cache throws (Redis down), the request goes through without
  limiting and a warning is logged (`Rate limiting is off for this request: the cache failed (...)`, with
  the exception), instead of a 500 on every endpoint. The internal `RateLimiter` takes an optional
  logger.
- Rate limit keys group IPv6 addresses by /64; an IPv4-mapped address (`::ffff:203.0.113.7`) counts as
  its IPv4 address, and IPv4 addresses one by one. This applies to whatever the `$clientIp` closure
  returns.
- Introspection has its own rate limit counter, `rateLimit.introspect` (default `[600, 60]`), instead of
  sharing `token`: a resource server that introspects on every request no longer exhausts `/token`, and
  `/token` no longer has to be loosened for it. `/revoke` still shares `token`.
- `tokenPrefix` is checked when `ServerConfig` is built (`"tokenPrefix" must be 1 to 16 lowercase letters
  or digits.`), not at the first issued token. New `TokenGenerator::isValidPrefix()`.
- Configuration parsing never lets a `TypeError` or a PHP warning escape: every wrongly typed value given
  to `ServerConfig::fromArray()`, `ResourceRegistry::fromArray()`, `ProtectedResource::fromArray()` or
  `Lifetimes::fromArray()` throws an `InvalidArgumentException` naming the setting, with its section
  (`"cimd.timeout" must be an integer.`, `"registration.mode" must be a string.`, `"lifetimes.access"
  must be an integer (seconds).`, `"defaultResource" must be a resource URL (a string).`, `"scopes" of the
  resource "..." must be an array.`). A resource whose settings are not an array (`'https://example.com/mcp'
  => 'Example MCP'`, or a list of URLs) is refused naming the resource. `cimd.allowedHosts` must list
  strings (other values used to be cast). `ResourceRegistry::fromArray()` now accepts `array<mixed>`.
  `ConfigurationTypesTest` feeds every setting values of the wrong types.
- Secrets in traces: every parameter that carries a token, a code, a verifier, a client secret, the
  `secret` or `initialAccessToken` setting, a form body or a token response is a `#[\SensitiveParameter]`
  (`TokenValidator::validate()`, `RefreshTokenRotator::rotate()`, `TokenRevoker::revokeForClient()`,
  `TokenGenerator::hash()`, `Pkce::verify()` and its helpers, `FormToken`, `ClientAuthenticator`,
  `ServerConfig::__construct()` and `fromArray()`, `IssuedTokens`, `ClientRegistrar::registrationResponse()`,
  the token and introspection handlers, `HttpResponder::json()`, `redirect()` and `page()`,
  `RedirectUrl::build()`, `Params::parse()`, the new personal token on its way to the connections page,
  the MCP bridge). `SecretsInTracesTest` renders the traces of failed refreshes, code
  exchanges, client lookups, introspections, revocations, bearer checks and configuration errors with
  `zend.exception_ignore_args=0` and a large `zend.exception_string_param_max_len`.
- Client ID Metadata Documents: a DNS lookup that gets no answer (a resolver timeout, SERVFAIL) is a
  temporary failure (`The client_id host could not be looked up right now.`), not remembered as a
  rejection, like a network error; a name without A or AAAA records stays a definite rejection.
  `DnsResolverInterface::resolve()` now documents that it throws a `RuntimeException` when the lookup
  itself failed; `SystemDnsResolver` does so when `dns_get_record()` fails (it used to answer `[]`).
- Connections page: a connection shows its grant, the scopes of its newest refresh token that was not
  rotated yet (or of its newest token without one), on purpose. It used to show whichever live token the
  storage returned last, and access and refresh tokens share their creation time, so after a down-scoped
  refresh the page could show the narrowed access token. `docs/pages.md` documents it, and that a
  connection revocation deletes the person's pending codes for that client on every resource.
- Tests: a login return URL never starts with `//` even when the PSR-7 implementation returns the raw
  path from `getPath()` (Guzzle and Laminas do; Nyholm collapses it, which hid the case); `/token` refuses
  a complete exchange whose body is not declared form-encoded; a `client_id` longer than 2048 characters
  is unknown; `revokeAllForClient()` deletes codes before revoking tokens (a twin of the subject test).
- CI: the workflow token is limited to `permissions: contents: read`.
- Docs: `Client authentication is required.` is the one other client authentication text (no client
  named at all); security notes on secrets in traces and on error descriptions; the DNS lookup is not
  bounded by `cimd.timeout` (`docs/security.md`, `docs/configuration.md`); `docs/storage.md` states
  exactly which races the tests replay.
- Introspection of a refresh token reports, as `scope`, what an access token refreshed from it would hold
  today (the grant narrowed by the client's scopes and the owner's `scopesFor()`, the same computation as
  a refresh, expanded the way an access token's scopes are), not the grant it stores. A refresh keeps the
  grant, so after a demotion the stored scopes can be wider than what the person has, and a resource
  server that wrongly checked only `active` and `scope` could have accepted the refresh token as a bearer
  with them. A refresh token that could not be refreshed any more (no scope left for the client or the
  owner, or its resource no longer declared) answers `{"active": false}`. `docs/endpoints.md` and
  `docs/security.md` now say that a resource server must accept only `"token_type": "Bearer"` and never a
  refresh token. New internal `ScopeResolver::refreshed()`, used by the refresh and by introspection;
  the internal `IntrospectHandler` constructor takes the `ScopeResolver` as a new last argument.
- A private-use redirect is named by its scheme with the colon: `ConsentView::redirectHost()` and
  `RedirectNoticeView::redirectHost()` return `claude.ai:` for `claude.ai:/callback` (they returned
  `claude.ai`), so a dynamic client with that redirect no longer gets "send this answer to claude.ai"
  and "Continue to claude.ai" on the redirect notice, and the consent page says "Your answer is sent to
  claude.ai:.". Custom templates that print `redirectHost()` show the colon too.
- Consent page wording: a self-registered client with a private-use redirect gets its own sentence, the
  new `Messages` key `consent.fromLocal` ("The request comes from an application on this computer. Your
  answer is sent to {redirect}."), instead of the `client.local` label dropped into `consent.from`
  ("The request comes from An application on this computer.").
- Secrets in traces: `ConsentView`'s `$fields` (they carry the `consent_token`), `ConnectionsView`'s
  `$formToken` and the connections renderer's hidden field value are `#[\SensitiveParameter]` too.
  `SecretsInTracesTest` now fails a code-carrying `/authorize` redirect whose response cannot be built
  (the code stays out of the trace of `HttpResponder::redirect()`), and pins the attribute by reflection
  on the parameters no failure can reach today (`RedirectUrl::build()`, `HttpResponder::redirect()`,
  `page()` and `json()`, the two view constructors, the hidden field helper).
- Names: tag characters are accepted only in the three RGI subdivision flags (U+1F3F4, the tags
  spelling `gbeng`, `gbsct` or `gbwls`, U+E007F: England, Scotland, Wales). Every other tag sequence is
  refused, however short: a cap on its length still let a flag spell `IGN OR!`, and several flags in one
  name could carry about 190 hidden ASCII characters.
- Refresh with a narrowed client: the client's registered scopes narrow the refreshed access token the
  way the owner's `scopesFor()` does (the grant expanded, kept where the expanded allowance contains it,
  reduced to the minimal set). A client an administrator narrowed from `content:write` to `content:read`
  used to get `invalid_scope` on refresh, and introspection showed its refresh token inactive, while its
  access token still worked as `content:read`; it now refreshes with a `content:read` access token, the
  new refresh token keeps `content:write`, introspection reports `content:read`, and the client widened
  again gets `content:write` back at the next refresh. Only a client that may hold none of the scopes is
  still refused (`invalid_scope`, inactive on introspection).
- Configuration: a non-empty list where a map is expected is refused with an `InvalidArgumentException`
  naming the setting, in `resources`, `lifetimes`, `registration`, `cimd`, `rateLimit`, a resource's
  settings, its `scopes` and its `implies` (`'scopes' => ['content:read', 'content:write']` used to
  declare the scopes `0` and `1`). An empty array stays an empty map; a map whose keys are exactly 0,
  1, 2, ... in order is a list to PHP and is refused as well. `ProtectedResource::fromArray()` and
  `Lifetimes::fromArray()` now document `array<mixed>`. `ConfigurationTypesTest` feeds a list to every
  map.
- Docs: the CIMD rule for native clients is stated apart from the dynamic registration one (a metadata
  document must say `"application_type": "native"` to use a private-use scheme), and a private-use
  client shows the consent page on every new connection only when it is public: a dynamic registration
  that omits `token_endpoint_auth_method` is confidential and its remembered consent skips the page
  (`docs/clients.md`, `docs/configuration.md`).

### Known issues

- Concurrent refreshes with the same refresh token can revoke the whole family: one request wins, the
  others get `invalid_grant` and the reuse detection fires a false `RefreshTokenReused`. The grace window
  does not absorb concurrent refreshes (only a retry after a lost response). Not fixed in this beta; it is
  being observed with claude.ai, and if real clients refresh in parallel a later beta will answer
  concurrent callers inside the grace window with the winner's response. Clients must send one refresh at
  a time per token. See `docs/security.md`.
- The DNS lookup of a metadata document host does not respect `cimd.timeout`: `SystemDnsResolver` uses
  the system resolver's timeouts and retries, so a slow authoritative server can hold a worker longer, and
  random subdomains escape the failure memory (only `rateLimit.cimd` slows them). Documented with
  mitigations in `docs/security.md`; a bounded lookup is planned before 1.0.0.
- No committed test covers the check of the address curl really connected to (`CURLINFO_PRIMARY_IP` in
  `CurlTransport`): removing it breaks nothing in the suite. It was verified by hand against local TLS
  servers; a seam to fake the primary IP is planned before 1.0.0.
- CI pins its GitHub Actions by tag, not by commit SHA, and has no job against the latest released
  `mcp/sdk` (the dev dependency is a `dev-main` commit aliased as 0.9.0). Both are planned before 1.0.0.
