# Errors

Every OAuth error has a code (`error`) and a text for developers (`error_description`). The text is
for the person who writes the client. It never contains internals, secrets or stack traces. Show
end users your own message.

Where an error goes depends on the endpoint:

- JSON endpoints (`/token`, `/register`, `/revoke`, `/introspect`) answer JSON:
  `{"error": "...", "error_description": "..."}` with the HTTP status below.
- `/authorize` redirects the error to the client's `redirect_uri` (with `error`, `error_description`,
  `state` and `iss`) once the client and the redirect URI are known to be valid. Before that it shows
  an HTML error page, because there is nowhere safe to send the person.
- Protected resources answer through `BearerTokenMiddleware` with a `WWW-Authenticate` challenge. See
  [protecting resources](protecting-resources.md).

The class `OAuthException` carries the code, description and status. Its `toArray()` gives the JSON
body. An exception also has an internal `temporary` flag, used to decide whether a stored client may
stand in for an unreachable metadata host. The flag never appears in a response.

## Error codes

| Code | HTTP status | Where | What the client developer should do |
| --- | --- | --- | --- |
| `invalid_request` | 400 (405 for a wrong method) | Everywhere | A parameter is missing, repeated or malformed. Read `error_description` and fix the request. Form endpoints need `application/x-www-form-urlencoded` |
| `invalid_client` | 401 | `/token`, `/revoke`, `/introspect`; `/authorize` as an error page | The client is unknown, revoked, uses the wrong authentication method, has the wrong secret, or its metadata document could not be used. Check the id and the secret. For a metadata document client, fix the document (see [troubleshooting](troubleshooting.md#cimd-fetch-failures)). A pruned dynamic client must register again |
| `invalid_grant` | 400 | `/token` | The code or refresh token is wrong, expired, used, or was issued to another client or redirect URI. Start the authorization again. Never retry a used refresh token |
| `unauthorized_client` | 400 | `/token`, `/authorize` | The client may not use this grant: wrong `grant_types`, a public client asking for client credentials, or no identity for the client. Fix the registration |
| `unsupported_grant_type` | 400 | `/token` | The `grant_type` is unknown, or `client_credentials` is disabled. Use `authorization_code`, `refresh_token` or `client_credentials` |
| `unsupported_response_type` | 400 | `/authorize` | Only `response_type=code` exists |
| `invalid_scope` | 400 | `/authorize`, `/token` | A scope is malformed, not declared by the resource, not allowed for the client or the person, or none can be granted |
| `invalid_target` | 400 | `/authorize`, `/token` | The `resource` is not declared, or does not match the code or the refresh token. Use the exact URL (see [troubleshooting](troubleshooting.md#invalid_target)) |
| `access_denied` | 403 (JSON); a redirect at `/authorize` | `/authorize`, `/register`, `/introspect` | The person denied the request, `canAuthorize()` refused, registration is closed, or introspection is disabled. Do not retry without the person's input |
| `invalid_client_metadata` | 400 | `/register` | The registration document is invalid: not JSON, too large, bad grant or response types, bad name or scope. Fix it |
| `invalid_redirect_uri` | 400 | `/register` | A redirect URI is not allowed. See [redirect URI rules](clients.md#redirect-uri-rules) |
| `invalid_token` | 401 | `/register` in `token` mode; protected resources | The token is missing, wrong, expired, revoked, for another resource, or its owner lost access. Get a new one (refresh, or authorize again) |
| `insufficient_scope` | 403 | Protected resources | The token is valid but lacks a required scope. Ask the person to authorize the missing scope |
| `server_error` | 500 | Everywhere | Something failed on the server. The details are in the server log. Retry later |
| `temporarily_unavailable` | 429 | `/authorize`, `/token`, `/register`, `/revoke`, `/introspect` | Rate limit reached. Wait for the number of seconds in the `Retry-After` header |

One more code exists for pages only: `not_found` (404) when the connections page is disabled.

## Messages of `invalid_grant`

These are the texts `/token` sends with `invalid_grant`:

| Text | Meaning |
| --- | --- |
| `The authorization code is invalid.` | Unknown code, or a code of another client |
| `The code_verifier does not match.` | The PKCE verifier is wrong or malformed |
| `The authorization code was already used.` | A replay. The tokens issued from the code were revoked |
| `The authorization code expired.` | Codes live 60 seconds by default |
| `redirect_uri does not match the authorization request.` | Send the same value as at `/authorize` |
| `The resource of this code no longer exists.` | The resource was removed from the configuration |
| `The person who approved this code no longer has access.` | `findBySubject()` returned `null` |
| `The refresh token is invalid.` | Unknown token, a token of another client, or not a refresh token |
| `The refresh token is no longer valid.` | Expired, or revoked |
| `The refresh token was already used.` | A replay outside the grace window. The family was revoked |
| `The refresh token is being rotated; try again.` | A retry arrived while the first request was still running |
| `The refresh token was revoked.` | It was revoked while the new pair was being issued |
| `The resource of this token no longer exists.` | The resource was removed from the configuration |
| `The owner of this refresh token no longer has access.` | `findBySubject()` or `forClient()` returned `null`. Nothing was revoked, so the connection works again when access returns |

## Generic messages

All client authentication failures say `Client authentication failed.` whatever the cause (unknown
client, wrong secret, wrong method, revoked), so an attacker learns nothing about which part was
wrong.

A failed metadata document download (network error, timeout, TLS problem, a document that is too
large) is reported only as `The client metadata document could not be fetched.` The text never
carries the low level error, so it cannot be used to probe your network. Other problems with a
document name the rule that was broken. See [troubleshooting](troubleshooting.md#cimd-fetch-failures).

## Handling errors in your own code

`OAuthException` is thrown by the services (`ClientRegistrar::register()`,
`ConnectionService::createPersonalToken()`, `TokenValidator` does not throw but returns a
`ValidationFailure`). If you call those yourself, catch it:

```php
use CakeDC\OAuth\Server\Exception\OAuthException;

try {
    $created = $server->connectionService()->createPersonalToken($owner, 'CI', $resource, ['read'], 30);
} catch (OAuthException $e) {
    return ['error' => $e->error, 'message' => $e->getMessage()]; // for example invalid_scope
}
```

`ClientRegistrar::create()` is for administrators and throws `InvalidArgumentException` for bad input.
