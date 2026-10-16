# Configuration

You configure the server with `ServerConfig::fromArray()`:

```php
use CakeDC\OAuth\Server\Config\ServerConfig;

$config = ServerConfig::fromArray([...]);
```

Types are strict: a number must be an integer (`3600`, not `"3600"`) and a flag must be `true` or
`false`. An unknown key anywhere (top level, or inside `lifetimes`, `registration`, `cimd`,
`rateLimit` or a resource) throws `InvalidArgumentException`, so a typo does not go unnoticed.

The same object can be built directly with `new ServerConfig(...)`, using named arguments
(`registrationMode`, `cimdEnabled`, `cimdAllowedHosts`, `cimdTimeout`, `cimdMaxBytes`, `cimdCacheMin`,
`cimdCacheMax`, `allowPrivateSchemes`, `rateLimits` and so on). The array form is what this page
documents.

## Top level keys

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `issuer` | string | required | Canonical URL of this server, for example `https://auth.example.com`. https, except on loopback hosts. No query, no fragment, no trailing slash. It appears in the metadata and in the `iss` of every authorization answer. It is always taken from this setting, never from the request |
| `secret` | string | required | At least 32 characters (for example 32 random bytes, hex or base64 encoded). Signs the consent and connections forms. Not used for tokens |
| `resources` | array | required | The resources tokens are issued for. See below |
| `defaultResource` | string | first resource | The resource used when a client sends no `resource` parameter |
| `routePrefix` | string | `/oauth` | Path of the endpoints below the issuer. Starts with `/`, does not end with `/` |
| `tokenPrefix` | string | `oauth` | Prefix of tokens and secrets: `<prefix>_at_...`. 1 to 16 lowercase letters or digits. Use your product name so leaked tokens can be traced |
| `lifetimes` | array | see below | How long codes and tokens live |
| `refreshTokens` | string | `always` | `always` issues a refresh token with every code exchange. `offline_access` only when the client asked for the `offline_access` scope |
| `registration` | array | see below | Dynamic client registration |
| `cimd` | array | see below | Client ID Metadata Documents |
| `clientCredentials` | bool | `true` | Enable the client credentials grant |
| `introspection` | bool | `true` | Enable the introspection endpoint |
| `personalTokens` | bool | `true` | Enable personal access tokens on the connections page. Off, existing personal tokens stop validating at once and creation is refused, while listing and revoking stay available |
| `connections` | bool | `true` | Enable the connections page. When `false` the page answers 404 |
| `rateLimit` | array | see below | Request limits per endpoint |
| `retentionDays` | int | `7` | Days revoked and expired tokens are kept before [pruning](operations.md) deletes them |

## `lifetimes`

All values are seconds.

| Key | Default | Meaning |
| --- | --- | --- |
| `code` | `60` | Authorization code |
| `access` | `3600` | Access token |
| `refresh` | `2592000` (30 days) | Refresh token. Each rotation gives the new one a fresh period |
| `family` | `31536000` (365 days) | Hard cap on a whole chain of refresh tokens. After it, the person must authorize again. Stored per token (`family_started_at`), so it survives pruning |
| `personalMax` | `7776000` (90 days) | Longest a personal token may live |
| `refreshReuseGrace` | `30` | Seconds in which a refresh token that was just rotated may be presented once more. `0` turns the grace off. See [security](security.md#the-refresh-grace-window) |

Every lifetime except `refreshReuseGrace` must be at least 1. `refreshReuseGrace` must not be
negative.

## `registration`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `mode` | string | `open` | `open`: anyone may register. `token`: only callers with `Authorization: Bearer <initialAccessToken>`. `closed`: the endpoint answers `access_denied` and is left out of the metadata |
| `initialAccessToken` | string | `null` | Required when `mode` is `token`. Choose a long random value |
| `allowPrivateSchemes` | bool | `false` | `true` lets native clients use private-use URI schemes, but only reverse domain names such as `com.example.app:/cb` (RFC 8252 section 7.1; `myapp:/cb` or `cursor://...` are refused). `false` limits redirect URIs to https and loopback http, as the MCP authorization spec requires. It applies to dynamic registration and to metadata documents. Clients you create with `ClientRegistrar::create()` may always use reverse domain schemes. Enable it on purpose, for example for mobile apps |

## `cimd`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | bool | `true` | Accept `client_id` values that are https URLs |
| `allowedHosts` | list of strings | `null` (any host) | Only fetch documents from these hosts, for example `['claude.ai']`. Matching ignores case and is exact (no wildcards). The list also applies to clients already cached: removing a host refuses its clients at the next request, with no fetch |
| `timeout` | int | `5` | Seconds to wait for the document |
| `maxBytes` | int | `10240` | Largest document accepted |
| `cacheMin` | int | `300` | Shortest time a fetched document is kept. Between `0` and `cacheMax` |
| `cacheMax` | int | `86400` | Longest time a document is kept, whatever the host's `Cache-Control` says. Also the extra time a stored client keeps working when its host is temporarily unreachable |

A host that sends `Cache-Control: no-store` or `no-cache`, or no `max-age`, gets `cacheMin`.

`timeout`, `maxBytes` and `cacheMax` must be positive. If `cimd.enabled` is `true` and `ext-curl` is
not loaded, the `AuthorizationServer` constructor throws `LogicException` unless you pass a transport.

## `rateLimit`

Each entry is `[max requests, window in seconds]`. Counting is per endpoint and per client address, in
a fixed window.

| Key | Default | Applies to |
| --- | --- | --- |
| `authorize` | `[30, 60]` | `/authorize` |
| `token` | `[60, 60]` | `/token`, `/revoke` and `/introspect` (they share one counter) |
| `register` | `[10, 3600]` | `/register` |
| `cimd` | `[10, 60]` | Metadata document fetches (`rateLimit.cimd`), counted per client address at `/authorize`, `/token`, `/revoke` and `/introspect`. Only a real download counts: a cached client never does, and neither does a repeat inside the one-minute failure memory |

You only list the keys you want to change. Limits take effect only when you pass a PSR-16 cache to
`AuthorizationServer` (the `$cache` argument). Without a cache nothing is limited. Both numbers must
be at least 1. The address is `REMOTE_ADDR` unless you pass a `$clientIp` closure. See
[deployment](deployment.md#the-client-ip-behind-proxies).

## Resources

`resources` maps a resource URL to its settings:

```php
'resources' => [
    'https://example.com/mcp' => [
        'name' => 'Example MCP',
        'scopes' => [
            'content:read' => 'Read your posts',
            'content:write' => 'Edit drafts',
            'content:publish' => 'Publish posts',
        ],
        'implies' => ['content:publish' => ['content:write'], 'content:write' => ['content:read']],
        'defaultScopes' => ['content:read'],
    ],
],
```

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | string | the host of the URL | Shown on the consent and connections pages |
| `scopes` | map | required | `scope name => description`. The description is what the person reads at consent. At least one scope |
| `implies` | map | `[]` | `scope => list of scopes`. A token holding the key also holds the listed scopes, transitively. Every name must be declared in `scopes` |
| `defaultScopes` | list | `[]` | Granted when a client asks for no scope. Must be declared in `scopes`. If it is empty and the client asks for nothing, the request fails with `invalid_scope` |

The resource URL must be in canonical form: lowercase scheme and host, no default port, no trailing
slash, no fragment. In the array form (`ServerConfig::fromArray()`, `ProtectedResource::fromArray()`) the
keys are canonicalized for you. A `ProtectedResource` built by hand with its constructor must already be
canonical and throws otherwise. Scope names are printable ASCII
without spaces, quotes or backslashes. `offline_access` cannot be a resource scope.

Scopes are checked at the time of use, not only when issued. A token holds its granted scopes plus
what they imply, limited to what the client and the person may hold today (`scopesFor()`) and to what
the resource still declares. Remove a scope from the configuration and live tokens lose it at once.

## Validation rules and messages

Invalid settings throw `InvalidArgumentException` when the config is built. The messages:

| Problem | Message |
| --- | --- |
| Issuer not canonical | `The issuer "..." is not canonical.` |
| Issuer with a query | `The issuer must not have a query.` |
| Issuer over plain http, not on loopback | `The issuer "..." must use https.` |
| Short secret | `The secret must have at least 32 characters.` |
| Bad route prefix | `"routePrefix" must start with "/" and not end with "/", like "/oauth".` |
| Bad `refreshTokens` | `"refreshTokens" must be "always" or "offline_access".` |
| Bad registration mode | `The registration mode must be "open", "token" or "closed".` |
| Token mode without a token | `Registration mode "token" needs an "initialAccessToken".` |
| A non-positive CIMD or retention number | `"cimdTimeout" must be positive.` (same for `cimdMaxBytes`, `cimdCacheMax`, `retentionDays`) |
| Bad cache range | `"cimdCacheMin" must be between 0 and "cimdCacheMax".` |
| Bad rate limit | `"rateLimit.token" must be [max requests, window seconds].` |
| Bad token prefix | `The token prefix must be 1 to 16 lowercase letters or digits.` (thrown when the server first creates a token, not when the config is built) |
| Unknown top level key | `Unknown OAuth server setting "..."`. |
| Missing required key | `The OAuth server setting "issuer" is required.` |
| Unknown nested key | `Unknown setting "cimd.foo".` |
| Unknown lifetime | `Unknown lifetime "..."`. |
| Lifetime too small | `The "access" lifetime must be at least one second.` |
| Negative grace | `"refreshReuseGrace" cannot be negative.` |
| Resource without scopes | `The resource "..." declares no scopes.` |
| Resource not canonical (a `ProtectedResource` built by hand) | `The resource "..." is not canonical; use "...".` |
| Unknown scope in `implies` or `defaultScopes` | `The resource "..." refers to the unknown scope "...".` |
| Invalid scope name | `"..." is not a valid resource scope.` |
| Unknown default resource | `The default resource "..." is not declared.` |
| Same resource twice | `The resource "..." is declared twice.` |

`AuthorizationServer::bearerMiddleware()` and `mcpTokenValidator()` also fail early with
`Resource "..." is not declared.` or `Scope "..." is not declared by the resource "...".`, so a typo in
a route does not become a runtime 401.

## A complete example

```php
$config = ServerConfig::fromArray([
    'issuer' => 'https://auth.example.com',
    'secret' => getenv('OAUTH_SECRET'),
    'routePrefix' => '/oauth',
    'tokenPrefix' => 'acme',
    'refreshTokens' => 'offline_access',
    'lifetimes' => [
        'access' => 1800,
        'refresh' => 1209600,
        'refreshReuseGrace' => 30,
    ],
    'registration' => [
        'mode' => 'open',
        'allowPrivateSchemes' => false,
    ],
    'cimd' => [
        'enabled' => true,
        'allowedHosts' => ['claude.ai'],
        'cacheMax' => 43200,
    ],
    'clientCredentials' => true,
    'introspection' => false,
    'personalTokens' => true,
    'connections' => true,
    'rateLimit' => [
        'authorize' => [60, 60],
        'token' => [120, 60],
        'cimd' => [20, 60],
    ],
    'retentionDays' => 14,
    'resources' => [
        'https://example.com/mcp' => [
            'name' => 'Example MCP',
            'scopes' => [
                'content:read' => 'Read your posts',
                'content:write' => 'Edit drafts',
            ],
            'implies' => ['content:write' => ['content:read']],
            'defaultScopes' => ['content:read'],
        ],
    ],
    'defaultResource' => 'https://example.com/mcp',
]);
```

Note: with `'allowedHosts' => ['claude.ai']` only metadata-document clients from claude.ai work.
Dynamically registered and hand-registered clients are not affected.
