# Endpoints

This page is the HTTP reference. Paths assume the issuer `https://auth.example.com` and the default
`routePrefix` of `/oauth`. Use `ServerConfig::endpointUrl()` to get the real URLs.

The JSON endpoints (metadata, token, register, revoke, introspect) answer `OPTIONS` preflights and
add CORS headers: `Access-Control-Allow-Origin: *`, methods `GET, POST, OPTIONS`, headers
`Authorization, Content-Type, MCP-Protocol-Version`, no credentials. Their responses are never cached
(`Cache-Control: no-store`), except the metadata. The two page endpoints (authorize and connections)
answer HTML or redirects and are not CORS enabled.

JSON errors always have this shape (see [errors](errors.md) for every code):

```json
{"error": "invalid_grant", "error_description": "The authorization code expired."}
```

A wrong method answers `405` with an `Allow` header and the error `invalid_request`.

## GET /.well-known/oauth-authorization-server

Authorization server metadata (RFC 8414). Clients read it to find the other endpoints.

- Method: `GET` (and `OPTIONS`).
- Path: `ServerConfig::metadataPath()`. When the issuer has a path the path is added after the
  well-known segment.
- Cache: `Cache-Control: public, max-age=300`.

```bash
curl -s https://auth.example.com/.well-known/oauth-authorization-server
```

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/oauth/authorize",
  "token_endpoint": "https://auth.example.com/oauth/token",
  "registration_endpoint": "https://auth.example.com/oauth/register",
  "revocation_endpoint": "https://auth.example.com/oauth/revoke",
  "introspection_endpoint": "https://auth.example.com/oauth/introspect",
  "scopes_supported": ["content:read", "content:write", "offline_access"],
  "response_types_supported": ["code"],
  "response_modes_supported": ["query"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
  "revocation_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
  "introspection_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
  "code_challenge_methods_supported": ["S256"],
  "client_id_metadata_document_supported": true,
  "authorization_response_iss_parameter_supported": true
}
```

Members that depend on settings: `registration_endpoint` is missing when registration is `closed`;
`introspection_endpoint` and its auth methods are missing when `introspection` is `false`;
`client_credentials` is missing from `grant_types_supported` when `clientCredentials` is `false`;
`client_id_metadata_document_supported` follows `cimd.enabled`.

## GET and POST /oauth/authorize

The authorization endpoint. The browser of the person visits it, never the client's server.

### GET: start

Query parameters. Each authorization parameter below may be sent at most once: a repeat of any of them is
refused (`client_id` and `redirect_uri` repeats give the error page). Repeats of other, non-OAuth
parameters (for example a tracking parameter that a proxy appends) are ignored. That leniency is
deliberate: RFC 6749 section 3.1 says request parameters must not be repeated, which the server
enforces for the parameters it reads, but a stray parameter it does not read cannot change the
meaning of the request, so it is not worth breaking a login over.


| Parameter | Required | Meaning |
| --- | --- | --- |
| `response_type` | yes | Must be `code` |
| `client_id` | yes | The client's id (a URL for a metadata document client) |
| `redirect_uri` | when the client has more than one | Must match a registered URI exactly. Loopback `http` URIs match on any port |
| `code_challenge` | yes | PKCE challenge: base64url of the SHA-256 of the verifier (43 characters) |
| `code_challenge_method` | yes | Must be `S256` |
| `resource` | no | The resource the token is for. Default: the default resource |
| `scope` | no | Space separated scopes. Default: the resource's `defaultScopes`. May include `offline_access` |
| `state` | recommended | Returned unchanged. Only printable ASCII (`%x20-7E`) is accepted: anything else gets a redirected `invalid_request` that omits `state` |

What happens:

1. The request is validated. Unknown client, bad or unregistered `redirect_uri`, or a repeated
   `client_id` or `redirect_uri`: an HTML error page (the server cannot know where to send the
   person, so it never redirects).
2. If nobody is signed in, `UserContextInterface::loginResponse()` is called, also when the request has
   any other error: the server never redirects to a client before the person is authenticated (RFC 9700
   section 4.11.2). After the login the browser comes back to the same URL and the request is
   validated again.
3. Any other error is then sent back to the client (`error`, `error_description`, `state` and `iss`), but
   automatically (a `302`) only when the redirect URI is trusted: the client was registered by an
   administrator (`ClientRegistrar::create()`), or the signed-in person already approved this client
   (for any resource). For a dynamically registered or metadata document client the person never
   approved, the error page names the destination host and offers a "Continue to ..." link with the
   same error, which the person may follow or not. A client secret does not make a dynamic client
   trusted: anyone can register one, with any https redirect URI.
4. `UserProviderInterface::canAuthorize()` and the scope rules decide whether the request may go on.
5. If the person already consented to these scopes and the client's identity is assured, the code is
   issued at once (a `302` to the client). The identity is assured for a confidential client, or when the
   redirect URI is `https` on a host that is not this computer. A public client with a loopback or
   private-use redirect URI always gets the consent page, which then says the client was approved
   before: any program on the person's computer can open the authorization URL with its own port and
   PKCE challenge (RFC 8252 section 8.6). Otherwise the consent page is shown.

Success is a redirect to the client: `redirect_uri?code=...&state=...&iss=https://auth.example.com`.

### POST: the decision

The consent form posts the same authorization parameters (as hidden fields) plus:

| Field | Meaning |
| --- | --- |
| `decision` | `approve` or `deny`. Anything else counts as a denial |
| `consent_token` | Signed token bound to this exact request, the shown scopes and the person. Expires after 15 minutes |

The answer is a `303` redirect to the client with the code (approve) or `error=access_denied`
(deny), for every client: the person saw the client and the host of its redirect URI on the consent
page. `303` makes the browser use `GET`, so the form data is not posted to the client. A form whose
token is missing, expired or changed answers `invalid_request` on an error page. A POST from someone
who is no longer signed in gets the error page, never a redirect. Other errors of the POST follow the
same trust rule as the GET.

Errors: `invalid_request`, `invalid_client`, `unsupported_response_type`, `unauthorized_client`,
`invalid_scope`, `invalid_target`, `access_denied`, `server_error`, `temporarily_unavailable` (rate
limit). See [errors](errors.md).

## POST /oauth/token

Exchanges a grant for tokens. The body is `application/x-www-form-urlencoded`. Any other content type
is refused. Unlike `/authorize`, there is no leniency here: any parameter sent more than once, whatever
its name, is refused with `invalid_request` (`/revoke` follows the same rule; `/introspect` refuses a
repeated `token`).

### Client authentication

| Client | How it authenticates |
| --- | --- |
| Public (`none`) | Sends `client_id` in the body, no secret |
| `client_secret_basic` | `Authorization: Basic base64(client_id:client_secret)` |
| `client_secret_post` | `client_id` and `client_secret` in the body |

A client must use the method it registered with. Sending two methods at once is refused. Every
authentication failure answers the same text, `Client authentication failed.`, and a failed Basic
attempt adds `WWW-Authenticate: Basic realm="oauth"`. The one exception is a metadata document client
whose document cannot be used: that `invalid_client` keeps its own message (for example `Clients from
example.org are not accepted.` or `The metadata document needs a client_name.`), so its developer can
fix it. See [troubleshooting](troubleshooting.md).

### Response

```json
{
  "access_token": "oauth_at_...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "content:read",
  "refresh_token": "oauth_rt_..."
}
```

`refresh_token` is present when the client may use refresh tokens and `refreshTokens` allows it. The
response is `Cache-Control: no-store`.

### `grant_type=authorization_code`

| Parameter | Required | Meaning |
| --- | --- | --- |
| `code` | yes | The code from the redirect |
| `code_verifier` | yes | The PKCE verifier (43 to 128 characters of `A-Z a-z 0-9 - . _ ~`) |
| `redirect_uri` | when the client has several | Must equal the one used at `/authorize` |
| `resource` | no | Must name the resource of the code |
| `client_id` / secret | per client | See above |

```bash
curl -s https://auth.example.com/oauth/token \
  -d grant_type=authorization_code \
  -d code=oauth_ac_... \
  -d code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk \
  -d redirect_uri=http://127.0.0.1:8123/callback \
  -d client_id=CLIENT_ID \
  -d resource=https://example.com/mcp
```

Checks, in this order: client authentication, the grant is allowed, the code exists and belongs to
this client, the verifier matches, the code was not used before, it is not expired, `redirect_uri`,
`resource`, the person still exists. A code used a second time revokes everything issued from it, but
only when the right verifier is presented, so a thief with only the code cannot cause that.

Errors: `invalid_request`, `invalid_client`, `invalid_grant`, `unauthorized_client`, `invalid_target`.

### `grant_type=refresh_token`

| Parameter | Required | Meaning |
| --- | --- | --- |
| `refresh_token` | yes | The refresh token |
| `scope` | no | A subset of the current scopes. Default: all of them |
| `resource` | no | Must name the token's resource |

```bash
curl -s https://auth.example.com/oauth/token \
  -d grant_type=refresh_token -d refresh_token=oauth_rt_... -d client_id=CLIENT_ID
```

Every refresh returns a new pair and retires the old refresh token. Presenting an old one again
revokes the whole family (see [security](security.md#refresh-token-rotation-and-reuse)). A client must
not refresh the same token from two places at once.

Errors: `invalid_request`, `invalid_client`, `invalid_grant`, `unauthorized_client`, `invalid_scope`,
`invalid_target`.

### `grant_type=client_credentials`

For a confidential client acting for itself. See [clients](clients.md#client-credentials).

| Parameter | Required | Meaning |
| --- | --- | --- |
| `scope` | no | Scopes wanted. Default: the resource's `defaultScopes` |
| `resource` | no | Default: the default resource |

```bash
curl -s https://auth.example.com/oauth/token -u CLIENT_ID:CLIENT_SECRET \
  -d grant_type=client_credentials -d resource=https://example.com/api -d scope=read
```

No refresh token is issued. Errors: `invalid_client`, `unauthorized_client` (public client, no
permission, or `forClient()` returned `null`), `unsupported_grant_type` (disabled), `invalid_target`,
`invalid_scope`.

Any other `grant_type` gives `unsupported_grant_type`; a missing one gives `invalid_request`.

## POST /oauth/register

Dynamic client registration (RFC 7591). The body is JSON (`Content-Type: application/json`, at most
16 KB).

| Member | Meaning |
| --- | --- |
| `redirect_uris` | Required. List of 1 to 10 URIs. See [clients](clients.md#redirect-uri-rules) |
| `client_name` | Display name, 1 to 255 characters, no control characters. Default: the host of the first redirect URI |
| `application_type` | `web` (default) or `native` |
| `token_endpoint_auth_method` | `none`, `client_secret_basic` (default) or `client_secret_post` |
| `grant_types` | Default `["authorization_code"]`. May add `refresh_token`. `client_credentials` is refused |
| `response_types` | Must be `["code"]` |
| `scope` | Space separated scopes the client may ask for. `offline_access` is accepted but not stored. A `scope` of only `offline_access` stores an empty list, so the client may then get no resource scope at all (`invalid_scope` at `/authorize`). Leave `scope` out to allow any |
| `client_uri`, `logo_uri` | https URLs |

`client_id` and `client_secret` sent by the caller are ignored. In `token` mode the request needs
`Authorization: Bearer <initialAccessToken>`.

```bash
curl -s https://auth.example.com/oauth/register -H 'Content-Type: application/json' -d '{
  "client_name": "My CLI",
  "application_type": "native",
  "redirect_uris": ["http://127.0.0.1/callback"],
  "token_endpoint_auth_method": "none",
  "grant_types": ["authorization_code", "refresh_token"]
}'
```

The answer is `201`:

```json
{
  "client_id": "5f2b...e9",
  "client_id_issued_at": 1767225600,
  "client_name": "My CLI",
  "redirect_uris": ["http://127.0.0.1/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "application_type": "native"
}
```

Confidential clients also get `client_secret` and `client_secret_expires_at` (`0`, never). The secret
is shown only here. The request is rate limited (`register`).

Errors: `invalid_client_metadata`, `invalid_redirect_uri`, `access_denied` (closed), `invalid_token`
(token mode), `temporarily_unavailable`.

## POST /oauth/revoke

Token revocation (RFC 7009). Form encoded. The client authenticates like at `/token`.

| Parameter | Required | Meaning |
| --- | --- | --- |
| `token` | yes | An access or refresh token of this client |

```bash
curl -s https://auth.example.com/oauth/revoke -d token=oauth_rt_... -d client_id=CLIENT_ID
```

Revoking a refresh token revokes its whole family. Revoking an access token revokes only that token.
The answer is `200` with `{}`, also for unknown tokens and tokens of other clients, so the endpoint
cannot be used to find out which tokens exist. A `TokenRevoked` event with the reason `client` is
dispatched when something was revoked. This endpoint uses the `token` rate limit.

Errors: `invalid_request`, `invalid_client`.

## POST /oauth/introspect

Token introspection (RFC 7662), for another service that needs to check this server's tokens.
Disabled with `'introspection' => false` (answers `access_denied`).

The caller must be a confidential client created with `allowIntrospection: true`. A public client, or
one without the permission, gets `invalid_client`. That permission is a high privilege: such a client
can introspect any token, including the refresh tokens of other clients, and learns the person's
subject, username and scopes. Give it only to your own trusted resource servers. A repeated `token`
parameter is refused with `invalid_request`, as at `/revoke`.

```bash
curl -s https://auth.example.com/oauth/introspect -u RS_ID:RS_SECRET -d token=oauth_at_...
```

An active access token:

```json
{
  "active": true,
  "scope": "content:read",
  "client_id": "5f2b...e9",
  "sub": "42",
  "username": "Ada Lovelace",
  "aud": "https://example.com/mcp",
  "exp": 1767229200,
  "iat": 1767225600,
  "token_type": "Bearer"
}
```

An active refresh token answers the same, without `username`, and with `token_type` `refresh_token`.
Anything else (unknown, revoked, expired, used, owner gone, client revoked) answers
`{"active": false}`. Introspecting a token does not count as using it: `last_used_at` does not change.
This endpoint uses the `token` rate limit.

Errors: `invalid_request`, `invalid_client`, `access_denied` (disabled).

## GET and POST /oauth/connections

The page where a signed-in person sees the applications they connected and manages personal access
tokens. See [pages](pages.md) and [personal tokens](personal-tokens.md).

- `GET`: anonymous visitors go to `loginResponse()`. Signed-in people get the page.
- `POST`: form encoded, needs `form_token`. The `action` field selects what to do:

| `action` | Other fields |
| --- | --- |
| `revoke_connection` | `family_id` |
| `revoke_token` | `token_id` (a personal token) |
| `create_token` | `name`, `resource`, `days`, and `scope:<name>=1` for each chosen scope |

After a revocation the browser is redirected back (`303`). After `create_token` the page is shown with
the new token, once. An invalid creation shows the page again with the message and status `422`.
A disabled page (`'connections' => false`) answers `404`. A missing or expired `form_token` answers
`invalid_request`.
