# Troubleshooting

Each entry has the symptom, the cause and the fix. Start by reading the `error` and
`error_description` of the response ([errors](errors.md)) and your log. Unexpected failures are
logged through the PSR-3 logger you pass to `AuthorizationServer` (nothing is logged without one), and
clients only receive `server_error`.

## Issuer mismatch in clients

**Symptom.** The client says the issuer does not match, refuses the metadata, or loops back to
discovery.

**Cause.** The `issuer` in the metadata must equal the URL the client used to find it, character for
character. The library takes the issuer from your configuration and never from the request. A trailing
slash, `http` instead of `https`, `www.` or a port that differs is enough to fail. When the issuer has a
path, the metadata lives at `/.well-known/oauth-authorization-server` followed by that path.

**Fix.** Set `issuer` to the exact public URL (no trailing slash). Fetch
`ServerConfig::metadataUrl()` with curl and compare `issuer` with the URL you typed. Check that a
proxy does not send people to another host name.

## `invalid_target`

**Symptom.** `/authorize` or `/token` answers `invalid_target` ("The requested resource is unknown." or
"The code was issued for another resource.").

**Cause.** The `resource` the client sent is not one of your configured resources, or it differs from
the one in the code or the refresh token. Resources are compared in canonical form: lowercase scheme and
host, default port removed, trailing slash removed, no fragment. The path and the query are compared as
they are. `https://example.com/mcp/` and `https://example.com/mcp` are the same resource,
`https://example.com/MCP` is not. The host name must be the one the client uses: `www.example.com` and
`example.com` are different resources.

**Fix.** Configure the resource with the exact URL clients use (the URL of the MCP endpoint). Use the same
string in `ProtectedResourceMetadata`, in `bearerMiddleware()` or `mcpTokenValidator()`, and in the
client. If a client sends no `resource`, the default resource is used.

## The redirect URI is not registered

**Symptom.** An HTML page says `"redirect_uri" is not registered for this client.`, or registration
fails with `invalid_redirect_uri`.

**Cause.** Matching is exact. A different path, a trailing slash, `localhost` against `127.0.0.1`,
`http` against `https`, or an uppercase letter in the path all fail. The only flexibility is the port of
a loopback `http` URI. At registration, the URI may break the [redirect URI
rules](clients.md#redirect-uri-rules): no fragment, no non-ASCII characters (use punycode), plain
host name, https, or loopback http (not for a dynamic registration that says `"application_type":
"web"`), and private schemes only for native clients and only when enabled.

**Fix.** Register the exact URI the client sends. For local tools register a loopback URI without a
port, such as `http://127.0.0.1/callback`, and send `"application_type": "native"` or leave it out (never
`"web"`). For a private scheme, set `registration.allowPrivateSchemes` to `true`. A client with several
registered redirect URIs must send `redirect_uri` at `/authorize` and at `/token`.

## The person sees an error page with a "Continue to" link

**Symptom.** Instead of going back to the application, `/oauth/authorize` shows "Authorization failed"
with a link "Continue to {host}".

**Cause.** The request had an error (for example a missing `code_challenge` or an unknown scope) and the
client's redirect URI is not trusted: the client registered itself (dynamic registration) or is a
metadata document client, and this person never approved it. The server does not send people to an
address it cannot vouch for (RFC 9700 section 4.11.2).

**Fix.** Fix the request in the client. The person can follow the link to give the error to the
client. A client registered with `ClientRegistrar::create()`, or one the person approved before, gets
the error as a redirect.

## Claude Code asks for consent every time

**Symptom.** Each new connection of Claude Code (or another local tool) shows the consent page,
although the person approved it before; the page says so.

**Cause.** By design. A public client with a loopback or private-use redirect URI cannot prove who it
is: any program on the computer can open the same URL with its own port and PKCE challenge, so a
remembered consent never approves it silently (RFC 8252 section 8.6).

**Fix.** None needed. Refresh tokens keep an existing connection alive without the page.

## The consent form expired

**Symptom.** "The consent form expired or was changed. Start again from the application." or "The
form expired. Reload the page and try again."

**Cause.** The signed form token is valid for 15 minutes, is bound to the exact request and the
signed-in person, and stops working when you change the `secret`. Opening the consent page, leaving it
for a long time, and then pressing Allow causes it. So does signing in as a different person in another
tab, or a caching layer that served an old page.

**Fix.** Start again from the application. If it happens at once, check that nothing caches the
authorize page and that all your PHP servers have the same `secret`.

## Login loops

**Symptom.** The person signs in, and is sent to the login again. Or the consent page never appears.

**Cause.** `currentOwner()` returns `null` for the authorize request, because the session cookie did
not come with it. Typical reasons: the session cookie is limited to a path that does not include
`/oauth/`, the cookie is `SameSite=Strict` (the request arrives from the client by a top-level redirect,
which `Lax` allows and `Strict` does not), the cookie is `Secure` but the request reached PHP as plain
http, or the login runs on another host name than the issuer. Another cause is a login that ignores the
`return` URL and always goes to the home page.

**Fix.** Use `path=/` and `SameSite=Lax`. Let the login and the authorize page share the same host
name. Make your login redirect to the return value passed to `loginResponse()` (after checking it is a
local path). Use `examples/standalone` as a reference.

## CORS errors from browser clients

**Symptom.** A browser tool (the MCP Inspector, a single page app) reports a CORS error on the metadata,
token or register request, or cannot read `WWW-Authenticate`.

**Cause.** A proxy removed the headers, or added its own copy (two `Access-Control-Allow-Origin` values
are refused), or your MCP route has no CORS layer. The authorization server's JSON endpoints send CORS
headers themselves and answer preflights with `204`.

**Fix.** Do not add CORS headers at the proxy for `/oauth/` and `/.well-known/`. Add a CORS layer in
front of your protected route, outside `BearerTokenMiddleware`, and expose `WWW-Authenticate`.
See [deployment](deployment.md#cors).

## CIMD fetch failures

**Symptom.** `invalid_client` for a client whose id is an https URL ("The client metadata document could
not be fetched." and similar).

**Cause.** The server could not use the client's metadata document. `error_description` names the
broken rule, except for download failures (network error, timeout, TLS problem, a document that is too
large), which only say `The client metadata document could not be fetched.` The reason is one of
these:

| Reason | Fix |
| --- | --- |
| The URL is not clean: it has a fragment, user information, an empty path, `.` or `..` segments, odd characters, or a host that is not a plain host name or IP address | Use a plain https URL with a path, such as `https://app.example.com/oauth/client.json` |
| The host is not in `cimd.allowedHosts` ("Clients from ... are not accepted.") | Add it, or remove the list |
| The host does not resolve | Fix DNS. Check from the machine that runs PHP |
| The host resolves to a private, loopback, link-local or reserved address (also when only one of several addresses is) | The document must be served from a public address. This is the SSRF protection. For tests, serve it publicly or use a fake transport |
| Timeout or connection error | The default is 5 seconds (`cimd.timeout`). Check egress firewalls and TLS certificates of the client's host |
| Redirects | The server never follows redirects. Serve the document at the exact `client_id` URL |
| Wrong content type | The media type must be `application/json`. Parameters such as `; charset=utf-8` are ignored |
| Too large | The default maximum is 10240 bytes (`cimd.maxBytes`) |
| HTTP error | 404 and 410 reject the client at once. 5xx and 429 are treated as temporary and a stored copy keeps working |
| The document is wrong | `client_id` must equal the URL, `client_name` and `redirect_uris` are required, `token_endpoint_auth_method` must be `none` |
| `ext-curl` is missing | `AuthorizationServer` throws `LogicException` at start. Install it or pass your own `HttpTransportInterface` |
| No usable redirect URI | The document's URIs all break the redirect URI rules |

Run `curl -i https://client.example/oauth/client.json` from the machine that runs PHP and compare.
Download failures are not logged by the library, so this is the way to see them.

## Rate limit `429`

**Symptom.** `temporarily_unavailable` with status 429 and a `Retry-After` header.

**Cause.** The limit for the endpoint was reached for the client address
([configuration](configuration.md#ratelimit)). Two common reasons: all traffic comes through a proxy,
so everybody has the proxy's address ([deployment](deployment.md#the-client-ip-behind-proxies)), or a
hosted client such as claude.ai may send many people's requests from a shared range of addresses.

For metadata document clients there is a separate counter, `rateLimit.cimd` (default 10 downloads per
minute per address), which only counts real downloads of unknown or expired documents. Hitting it looks
the same (429 with `Retry-After`; on `/authorize` an error page, never a redirect). A client that
repeats a broken `client_id` URL is not counted again for 60 seconds: the failure is remembered, so after
fixing the document wait a minute before retrying.

**Fix.** Configure a `$clientIp` closure that reads the real address. Raise the limits, for example
`'rateLimit' => ['token' => [300, 60]]`. `/revoke` and `/introspect` share the `token` counter. Wait for
`Retry-After` seconds.

## `invalid_client` after pruning

**Symptom.** A dynamically registered client that worked before now gets `invalid_client` ("Client
authentication failed." or "This client is unknown.").

**Cause.** [Pruning](operations.md#pruning) deletes dynamic clients that are old, unused and have no live
tokens. A client that comes back after weeks finds itself gone.

**Fix.** The client should register again (`POST /oauth/register`). This is normal behaviour for dynamic
registration. Metadata document clients are fetched again automatically. If you need long-lived clients,
create them with `ClientRegistrar::create()`, which are never pruned.

## Clock skew

**Symptom.** Tokens or codes seem to expire at once, or never. Form tokens are "expired" right after they
were issued.

**Cause.** The servers disagree about the time (several PHP servers, a container with a wrong clock).
All lifetimes use the server's clock (`ClockInterface`) and times are stored in UTC. A database server in
a different time zone does not matter, because times are written and read in UTC by the library, but a
clock that is minutes off does.

**Fix.** Run NTP (`chrony` or `systemd-timesyncd`) on every server. Pass a `ClockInterface` only in
tests.

## Everything is `401` on protected routes

**Symptom.** `WWW-Authenticate: Bearer` without an error, although the client sends a token.

**Cause.** The `Authorization` header does not reach PHP (Apache with PHP-FPM or CGI drops it), or a
proxy strips it.

**Fix.** See [deployment](deployment.md#apache) for the `SetEnvIf` line, and check the header with a
small script that prints `getallheaders()`.

## `invalid_token`: "issued for another resource"

**Symptom.** A valid token is refused on one route.

**Cause.** The token was issued for resource A and the route uses `bearerMiddleware()` for resource B.
Tokens work only on their resource.

**Fix.** Use the middleware of the right resource for the route, or give the client a token for the
right `resource`.
