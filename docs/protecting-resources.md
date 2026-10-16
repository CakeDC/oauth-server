# Protecting resources

This page is for the code that serves your API or MCP endpoint and must accept only valid tokens.

## `BearerTokenMiddleware`

Ask the server for a middleware that belongs to one resource:

```php
$middleware = $server->bearerMiddleware(
    'https://example.com/api',                                       // the resource
    'https://example.com/.well-known/oauth-protected-resource/api', // optional metadata URL
    ['read'],                                                        // optional required scopes
);
```

`bearerMiddleware(string $resource, ?string $resourceMetadataUrl = null, array $requiredScopes = [])`
returns a PSR-15 `MiddlewareInterface`. It throws `InvalidArgumentException` at build time when the
resource is not declared, or when a required scope is not declared by that resource. A typo shows
up when you build the route, not as a 401 in production.

Use it with any PSR-15 stack:

```php
$response = $middleware->process($request, $yourApiHandler);
```

For each request it:

1. Reads `Authorization: Bearer <token>`.
2. Validates the token for this resource (see below).
3. Checks that the token holds every required scope.
4. Adds two attributes to the request and calls your handler.

### Request attributes

| Attribute | Type | Content |
| --- | --- | --- |
| `ValidatedToken::class` | `ValidatedToken` | The token with its owner, client, resource and scopes |
| `ResourceOwner::class` | `ResourceOwner` | The person the token acts for, freshly loaded through `findBySubject()`; for a client credentials token, the identity your `forClient()` returns |

```php
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Token\ValidatedToken;

public function handle(ServerRequestInterface $request): ResponseInterface
{
    $owner = $request->getAttribute(ResourceOwner::class);
    $token = $request->getAttribute(ValidatedToken::class);
    if ($token->hasScope('write')) {
        // ...
    }

    return new Response(200, ['Content-Type' => 'application/json'], json_encode(['user' => $owner->subject]));
}
```

Use `$owner->identity` to get your own user object back. Do not trust anything else the client sent
about who they are.

### Responses and `WWW-Authenticate`

Failures are JSON responses with a `WWW-Authenticate: Bearer ...` header (RFC 6750). Members, when
they apply: `resource_metadata="<url>"` (when you passed one), `scope="a b"` (the required scopes),
`error="..."` and `error_description="..."`.

| Case | Status | Header | Body |
| --- | --- | --- | --- |
| No `Authorization` header, or another scheme, or an empty bearer | 401 | `Bearer resource_metadata="...", scope="read"` | `{}` |
| Malformed header | 400 | `Bearer resource_metadata="...", error="invalid_request", error_description="Malformed Authorization header."` | error object |
| Unknown, revoked, expired or foreign token, or owner gone | 401 | `Bearer resource_metadata="...", error="invalid_token", error_description="..."` | error object |
| Valid token, missing scope | 403 | `Bearer resource_metadata="...", scope="read", error="insufficient_scope", error_description="The access token lacks a required scope."` | error object |

With no token the challenge has no `error`, as RFC 6750 asks, and the body is an empty object `{}`.
Clients use the `scope` and `resource_metadata` members to find out what to ask for.

The `error_description` of an `invalid_token` answer tells the developer why:

- `The access token is invalid.` (unknown, or a refresh token)
- `The access token was revoked.`
- `The access token expired.`
- `The access token was issued for another resource.`
- `The client of this access token was revoked.`
- `The owner of this access token no longer has access.`
- `The token no longer grants any scope.` (the computed scopes are empty, see below)
- `Personal access tokens are disabled.` (a personal token while `personalTokens` is off)

### Protected resource metadata URL

`resource_metadata` points to the RFC 9728 document of your resource. It tells clients which
authorization server to use. The library names the URL in challenges, but your application serves the
document. A minimal one:

```json
{
  "resource": "https://example.com/api",
  "authorization_servers": ["https://auth.example.com"],
  "scopes_supported": ["read", "write"],
  "bearer_methods_supported": ["header"]
}
```

Serve it at `/.well-known/oauth-protected-resource` followed by the resource's path (here
`/.well-known/oauth-protected-resource/api`). With the MCP SDK the SDK serves it for you. See
[MCP](mcp.md).

### CORS preflights

Browser clients send a preflight (`OPTIONS` with an `Access-Control-Request-Method` header) without a
token. The middleware lets exactly those requests through to your handler, without the attributes
above, and your handler must answer them without side effects. Any other `OPTIONS` request is
challenged like every other request.

Put your CORS layer outside this middleware, so it adds its headers to the 401 and 403 answers as
well, and expose the `WWW-Authenticate` header (`Access-Control-Expose-Headers`).

## Using `TokenValidator` directly

When you are not on PSR-15, or need your own responses, validate by hand:

```php
use CakeDC\OAuth\Server\Token\ValidatedToken;
use CakeDC\OAuth\Server\Token\ValidationFailure;

$result = $server->tokenValidator()->validate($bearer, 'https://example.com/api');
if ($result instanceof ValidationFailure) {
    // $result->error is 'invalid_token'; $result->description says why.
    return unauthorized($result->description);
}
// $result is a ValidatedToken.
```

`validate(string $token, string $resource, bool $touch = true): ValidatedToken|ValidationFailure`.
It throws `InvalidArgumentException` when `$resource` is not declared (a configuration error).

With `$touch` set to `true` a use is recorded (`last_used_at` of the token and its client, at most once
a minute per token). Pass `false` to look without recording, as introspection does.

## `ValidatedToken`

| Property | Type | Meaning |
| --- | --- | --- |
| `token` | `Token` | The stored token: `id`, `type` (`access` or `personal`), `subject`, `subjectType`, `resource`, `scopes`, `createdAt`, `expiresAt`, `name` and more |
| `owner` | `ResourceOwner` | Its owner, loaded now: `findBySubject()` for a person's token, `forClient()` for a client credentials token |
| `client` | `Client` or `null` | The client. `null` for personal tokens |
| `resource` | `ProtectedResource` | The resource |
| `scopes` | `list<string>` | Scopes held right now, implied ones included |

`hasScope(string $scope): bool` tells whether the token holds a scope.

## Scopes are computed at check time

`scopes` is not a copy of what was granted. It is computed on every request:

1. Start with the scopes granted to the token.
2. Add the scopes they imply (through `implies`, transitively).
3. Keep only what the client may hold (its registered scopes, if it has a limit).
4. Keep only what the person may hold now (`scopesFor()`).
5. Keep only what the resource still declares.

If the result is empty the token is refused outright (`invalid_token`, `The token no longer grants any
scope.`): a token that holds nothing is not an authenticated request with no permissions. A refresh applies
the client and person allowances (steps 3 and 4) to the new access token, reduced to the minimal set (a
client narrowed from `content:write` to `content:read` gets a `content:read` token), and answers
`invalid_scope` when the client may hold none of the scopes, `invalid_grant` when the person may hold none.
The new refresh token keeps the scopes of the one presented (minus scopes the resource no longer declares),
so a person promoted again, or a client widened again, gets the scopes back at the next refresh.

So a role change, a removed scope in the configuration or a narrowed client takes effect at the next
request, without revoking anything. A token for `content:publish` that implies `content:write` passes a
`content:write` check.

Personal tokens (`personal` type) follow the same rules, and have no client.
