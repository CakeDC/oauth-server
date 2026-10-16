# Security

This page explains who the library defends against, how it follows the current OAuth security
advice (RFC 9700), what the defaults mean, and what to check before you go live. The tests behind each
item are in `tests/Security/`.

## Threat model

| Attacker | Wants | Main defences |
| --- | --- | --- |
| A malicious or sloppy client | Tokens for people who never agreed, or more access than agreed | Consent page naming the real host, exact redirect URI matching, scopes checked at use, tokens bound to one resource |
| Someone who registers a client to phish | To use your domain as a trampoline to their site (open redirect) | No redirect before the person signs in; errors go back automatically only to trusted redirect URIs |
| A program on the person's computer | A code for a local client the person approved before (any loopback port, its own PKCE challenge) | A public loopback or private-scheme client always gets the consent page (RFC 8252 section 8.6) |
| Someone who sees a code or a token (browser history, logs, a proxy, a malicious app on the same phone) | To use it | PKCE S256 on every code, single-use short-lived codes, short access tokens, tokens never in URLs or logs, `no-store` and `no-referrer` pages |
| A website that tricks a signed-in person | To approve a client for them (CSRF, clickjacking) | Signed form tokens bound to the request and the person, no page can be framed |
| A rogue authorization server in the client's list | To make a client send it the code meant for another server | `iss` on every authorization answer |
| Someone who reads your database | Working tokens and secrets | Only SHA-256 hashes of tokens, codes and client secrets are stored |
| Someone who controls a `client_id` URL | To make your server fetch internal addresses (SSRF) | Strict URL and address checks, pinned connection, no redirects, limits |
| An anonymous abuser | To fill your database, guess secrets or exhaust resources | Rate limits, closed or token-protected registration, size limits, pruning |
| A person (or their stolen account) who loses access | To keep using tokens after losing access | The owner and the scopes are checked again on every request |

## RFC 9700 item by item

| Item | How the library handles it | Test class |
| --- | --- | --- |
| Insufficient redirect URI validation | Exact matching, no normalisation. For loopback `http` redirects only the port may differ. Dangerous schemes and odd characters are refused at registration. A dynamic registration that says it is a `web` client may not register loopback `http`; private-use schemes are off by default. Nothing is ever sent to an unregistered URI | `RedirectUriValidationTest` |
| Credential leakage through Referer, browser history, and access token leakage | Pages are `no-store` with `Referrer-Policy: no-referrer`. Only the authorization code travels in a redirect. A token in a query string is ignored. Logs never contain secrets | `CredentialLeakageTest` |
| Mix-up attacks | Every authorization answer, errors included, carries `iss` (RFC 9207). The issuer always comes from your configuration, never from the request's `Host` | `MixUpTest` |
| Authorization code injection, PKCE downgrade | PKCE with S256 is mandatory for all clients, confidential ones too. A code is bound to its client, its redirect URI and its challenge. Codes live 60 seconds and work once. The verifier is checked before the server reacts to a used code | `AuthorizationCodeInjectionTest` |
| Access token privilege restriction | A token is bound to one resource (RFC 8707) and works nowhere else. Scopes are recomputed on every request. Access tokens live one hour by default | `AccessTokenPrivilegeTest` |
| Open redirection | The server redirects only to registered redirect URIs, and the login return URL is a single-slash relative path. Backslashes and control characters are refused. Section 4.11.2: nobody is redirected before signing in (an anonymous visitor gets the login, and the request is validated again afterwards), and an error is redirected automatically only to a trusted redirect URI: a client an administrator registered, or one the person approved before. For any other client (dynamic or metadata document, whatever its authentication method) the error page names the destination host and offers a link. "Deny" on the consent page always goes back, because the page showed the client and its host | `OpenRedirectTest` |
| 307 redirect | After the consent POST the browser is sent back with `303`, so it never repeats the form post (with the person's data) at the client | `RedirectStatusTest` |
| TLS terminating reverse proxies | The issuer and every resource must be https, except on loopback hosts. They are configured, never guessed from forwarded headers | `TransportSecurityTest` |
| Refresh token protection | Rotation on every use, reuse detection that revokes the family, binding to the client, a hard cap on the family's life | `RefreshTokenProtectionTest` |
| Cross-site request forgery | `state` comes back unchanged. The consent decision needs a form token bound to the request, the shown scopes and the person | `CsrfTest` |
| Clickjacking | No page can be framed (`X-Frame-Options: DENY` and a CSP with `frame-ancestors 'none'`) | `ClickjackingTest` |
| Client impersonating a resource owner | Client credentials tokens have the subject type `client`. A client can never pass for a person with the same id | `ClientImpersonationTest` |

Other classes: `SecretsTest` (hashes only, constant-time comparison), `SsrfTest` (metadata document
fetching), `AbuseTest` (rate limits and registration control), `LiveIdentityTest` (tokens follow the
person), all in `tests/Security/`.

## Defaults and what changing them does

| Setting | Default | Weakens when | Strengthens when |
| --- | --- | --- | --- |
| `lifetimes.access` | 3600 | Raised. A stolen access token works longer | Lowered. More refresh traffic |
| `lifetimes.code` | 60 | Raised | Lowered |
| `lifetimes.refresh` | 30 days | Raised | Lowered. People re-authorize more often |
| `lifetimes.family` | 365 days | Raised or kept as is: a stolen refresh token chain can live that long | Lowered: people must authorize again after that period |
| `lifetimes.refreshReuseGrace` | 30 | Raised. A longer window for a thief to use a stolen token before it is detected | `0` disables the grace. Strictest, but a lost response then costs a re-authorization |
| `lifetimes.personalMax` | 90 days | Raised. Long-lived tokens in scripts | Lowered |
| `refreshTokens` | `always` | | `offline_access`: refresh tokens only for clients that ask, and the person sees "Stay connected" |
| `registration.mode` | `open` | | `token` or `closed` |
| `registration.allowPrivateSchemes` | `false` | `true`: custom schemes can be claimed by any app on a device, and MCP requires localhost or https redirect URIs. Dangerous schemes stay refused | Kept `false` |
| `cimd.allowedHosts` | any host | | A list of hosts you expect |
| `rateLimit.cimd` | `[10, 60]` | | Lower it if you only expect a few clients |
| `rateLimit.*` | 30, 60 and 10 per window | Raised or no cache: no limiting at all | Lowered |
| `introspection` | `true` | | `false` if you do not need it |
| `clientCredentials` | `true` | | `false` if you do not need it |
| `personalTokens` | `true` | | `false` if you do not need it. Existing personal tokens stop working immediately |

Turn off what you do not use. Every endpoint you leave on is surface you must watch.

## Refresh token rotation and reuse

Every refresh returns a new access and refresh pair and retires the presented refresh token. If a
retired refresh token is presented again, somebody holds a copy: the real client or a thief. The
server cannot tell which, so it revokes the whole family (every token of that authorization), fires
`RefreshTokenReused` and answers `invalid_grant`. The person must authorize again.

Related rules:

- Presenting a refresh token that was revoked, while its family still has a live token, counts as
  reuse, because somebody else holds a newer pair.
- A refresh token whose owner no longer exists (`findBySubject()` returns `null`) is refused with
  `invalid_grant` and nothing is revoked, so the connection works again if the person is reactivated.
  A replay outside the grace window still revokes the family.
- The family lifetime (`lifetimes.family`) is a hard cap. It is stored with every token, so it survives
  pruning.
- A refresh token is bound to its client. Another client, or a confidential client that only sends its
  `client_id`, cannot use it.
- Clients must serialize refreshes per token. Three or more concurrent refreshes with the same token
  can revoke the family, and so can two concurrent grace retries.

## The refresh grace window

Networks fail. A client may send a refresh, the server may rotate the token, and the response may
never arrive. The client then retries with the old token, which looks exactly like a replay.

The grace window (`lifetimes.refreshReuseGrace`, 30 seconds) handles this. If the old token is
presented again within the window **and the pair issued by the first rotation was never used**, the
server issues a fresh pair and revokes the first one (event `TokenRevoked` with reason `grace`). Any
other reuse revokes the family.

The trade-off: for those seconds, a thief who copied the old refresh token could also get a pair. The
person's real client then holds a revoked token, and its next refresh counts as reuse, so the family is
revoked and the thief is cut off too. The window bounds the damage to its length. If you cannot accept
that, set it to `0`. Then a lost response costs one re-authorization.

`RefreshTokenReused` is not proof of theft. Buggy clients cause it too.

## Authorization codes and consent

- Tokens are issued before the code is marked used. If two requests race for one code, the loser
  revokes both families. A used code presented with the right verifier revokes what came from it. A
  used code presented without the right verifier revokes nothing, so a thief who only has the code
  cannot cause damage.
- The consent form token (`consent_token`) is bound to the request fingerprint, the exact scopes shown
  (including `offline_access`) and the person. A remembered consent covers `offline_access` only if it
  was granted. "Stay connected" follows `refreshTokens`.
- A remembered consent skips the page only when the client's identity is assured (RFC 8252 section
  8.6): a confidential client, which must present its secret to redeem the code, or an `https` redirect
  URI on a host that is not this computer. For a public client with a loopback (`localhost`,
  `*.localhost`, `127.0.0.0/8`, `[::1]`, http or https) or private-use redirect URI, whoever opens the
  authorization URL chooses the port and the PKCE challenge, so the consent page is always shown, with a
  line saying the client was approved before. The consent page warns for exactly these redirects: it
  uses the same classification (`Support\HostClass`) as the consent memory, and the unspecified
  addresses `0.0.0.0` and `::`, which reach the local machine on macOS and Linux, count as this
  computer. A local client therefore shows the page on every new connection; its refresh tokens keep an
  existing connection alive without it.
- Names: the consent page headlines a self-registered client by the host of its redirect URI and shows
  the name it declared only as a quoted, unverified line, so a client called `claude.ai` cannot
  produce the title or heading of the real one. Client and token names reject Unicode control and
  format characters (`Cc`, `Cf`: bidirectional overrides, zero-width characters), names without a
  visible character, and, at dynamic registration, names that are host names or IP addresses. Length
  limits count characters.
- Nothing checks `canAuthorize()` after `/authorize`. When your policy changes, revoke the person's
  tokens with `TokenRevoker::revokeAllForSubject()`.

## Secrets and tokens at rest

- Tokens, codes and client secrets are random (256 bits), prefixed, and stored as SHA-256 only. A
  database leak does not give working credentials.
- Client secrets are compared with `hash_equals`.
- Client authentication failures all say `Client authentication failed.`
- The `secret` setting signs forms only. It is not used for tokens. If it leaks, an attacker could
  forge consent forms for signed-in people, so keep it private and long (at least 32 characters, for example 32 random bytes, hex or base64
  encoded).
- `FormToken` expires after 15 minutes.

## SSRF protections for metadata documents

When a request names an https URL as `client_id`, the server downloads that URL. A hostile client could
point it at your internal network. The fetcher defends in layers:

1. The URL must be a clean https URL: RFC 3986 characters only, no fragment, no user information, no
   empty or `/` path, no `.` or `..` segments (even percent-encoded), and a strict host (`HostName`).
   This check runs before any DNS lookup.
2. If `cimd.allowedHosts` is set, only those hosts are fetched.
3. Every address the host resolves to is checked, and one bad address refuses the whole host. IPv4
   addresses in these ranges are denied: `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`,
   `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`, `192.0.2.0/24`, `192.88.99.0/24`,
   `192.168.0.0/16`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4`, `240.0.0.0/4`
   and `255.255.255.255/32`. IPv6 is an allowlist: only global unicast `2000::/3`, minus `2001::/23`,
   `2001:db8::/32`, `2002::/16` and `3fff::/20`.
4. The connection goes to the address that was checked (`CURLOPT_CONNECT_TO`) and the address curl
   really used is verified afterwards (`CURLINFO_PRIMARY_IP`). A DNS answer that changes between the
   check and the connection does not help an attacker.
5. No proxy, no redirects, https only, the response media type must be `application/json` (parameters such as a charset are ignored), and there is a
   size limit (`cimd.maxBytes`) and a time limit (`cimd.timeout`).
6. A failed download gives clients only a generic message, so the error cannot be used to probe your
   network. Other problems name the rule that was broken.

7. Fetches are budgeted per client address (`rateLimit.cimd`, 10 per minute by default), so one address
   cannot make your server download documents without end or fill the client table with rows. The count
   happens just before a download, never for a cached client. A failed fetch (a definite rejection or a
   temporary error) is remembered per `client_id` for 60 seconds in the PSR-16 cache, so repeating the
   same bad URL fails at once without a new download. Both need the cache argument of
   `AuthorizationServer`; without one nothing is limited or remembered. Over the budget, `/authorize`
   shows the error page with status 429 (never a redirect to the client) and `/token`, `/revoke` and
   `/introspect` answer 429 with `Retry-After`.

Fetched documents are cached as rows. Stored clients keep working for a limited time when their host
is temporarily unreachable (network error, timeout, 5xx or 429): until `expiry + cacheMax`. Definite
rejections (404, 410, a changed `client_id`, a host no longer allowed) apply at once. A revoked client
stays revoked: `saveClient()` never clears `revokedAt`.

## Abuse controls

- Rate limits per client address on `/authorize`, `/token` (shared with `/revoke` and `/introspect`) and
  `/register`. They need a PSR-16 cache. Counting is not atomic across processes, so a few extra requests
  can pass under load. That is fine for abuse control, not for exact quotas.
- Registration can be `closed` or protected by an initial access token (`token` mode). The token is
  compared in constant time, and failed guesses are counted by the rate limit.
- Request bodies are bounded: registration at 16 KB, metadata documents at `cimd.maxBytes`.
- Pruning removes dynamic and metadata document clients that are more than 24 hours old, unused for
  `retentionDays` and without live tokens.

## What the library does not do for you

- **Your login.** Protect it (rate limits, MFA, session fixation: regenerate the session id on login).
- **Policy.** `canAuthorize()` and `scopesFor()` decide who may do what. Write them carefully.
- **Your resource server.** After `BearerTokenMiddleware` you still check that the owner may touch the
  record they ask for.
- **Transport.** Terminate TLS. See [deployment](deployment.md).
- **Your logs.** Do not log `Authorization` headers or form bodies.

## Production checklist

- [ ] The issuer and every resource are https, spelled exactly as clients use them.
- [ ] `secret` is at least 32 characters (for example 32 random bytes, hex or base64 encoded), comes from the environment and is not in version control.
- [ ] A cron job runs `Pruner` daily ([operations](operations.md#pruning)).
- [ ] A shared PSR-16 cache (APCu, Redis, Memcached) is passed to `AuthorizationServer` for rate limits.
      `ArrayCache` is for tests only: each process has its own.
- [ ] A `$clientIp` closure reads the real client address behind your proxy, and trusts only your
      proxy ([deployment](deployment.md#the-client-ip-behind-proxies)).
- [ ] `cimd.allowedHosts` lists the hosts you expect, if you only serve known clients.
- [ ] Registration is `closed`, or `token` mode, if you do not need open registration.
- [ ] Features you do not use are off: `introspection`, `clientCredentials`, `personalTokens` (turning it off also stops existing personal tokens).
- [ ] `tokenPrefix` names your product.
- [ ] The database user can only touch the four tables, and backups are encrypted.
- [ ] Your CORS layer exposes `WWW-Authenticate` on protected routes.
- [ ] Revocation is wired to events that matter to you: password change, account removal, role
      change ([operations](operations.md)).
- [ ] You listen to `RefreshTokenReused` and `TokenRevoked` for monitoring.
- [ ] You ran `tests/Conformance/run.sh` against your build, if you changed it
      ([conformance](conformance.md)).
