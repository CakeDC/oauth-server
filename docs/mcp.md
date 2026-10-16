# MCP servers

The Model Context Protocol (MCP) lets AI assistants call tools in your application. Its HTTP
authorization uses OAuth 2.1: your MCP endpoint is the resource server and this library is the
authorization server. Everything an MCP client needs is covered: metadata discovery (RFC 8414),
Client ID Metadata Documents, dynamic registration, PKCE S256, the `resource` parameter and the `iss`
parameter.

This page shows how to protect an endpoint built with the official MCP PHP SDK
(`mcp/sdk`). The SDK is still in development, so check its documentation for the exact transport and
builder calls. The authorization pieces below are the SDK classes this library was tested against.

For CakePHP, use the `cakedc/cakephp-mcp` plugin together with `cakedc/cakephp-oauth-server`. They wire
everything for you.

## Install

```bash
composer require "mcp/sdk:^0.9" cakedc/oauth-server nyholm/psr7
```

The bridge needs **mcp/sdk 0.9 or newer**. If no 0.9 release of mcp/sdk is published yet when you read
this, require its main branch instead (`composer require mcp/sdk:dev-main`). mcp/sdk 0.8 has the
validator interface but not the `Mcp\Server\Authorization\AccessToken` class, and its
`AuthorizationResult::allow()` takes an array, so a bridge built on it would fail on every valid token.

`mcp/sdk` is a suggestion of this package, not a requirement. `mcpTokenValidator()` (and the bridge's
constructor) check the SDK when they are called and throw a `LogicException` that names the minimum
version: `The MCP SDK bridge requires mcp/sdk 0.9 or newer: ...` when the SDK is missing or older. The
check runs once, when you build the validator at boot, not on every request. The rest of the library
works with any mcp/sdk version installed, or none.

## The pieces

| Piece | From | Job |
| --- | --- | --- |
| `AuthorizationServer::mcpTokenValidator($resource)` | this library | A token validator in the SDK's format |
| `AuthorizationMiddleware` | SDK | Checks the bearer token and the scope policy, answers 401 and 403 |
| `ProtectedResourceMetadata` | SDK | Describes your MCP endpoint (RFC 9728), and its URL goes into the challenges |
| `ProtectedResourceMetadataMiddleware` | SDK | Serves that description |
| `ScopePolicy` | SDK | Which scopes each method or tool needs |

`mcpTokenValidator(string $resource): Bridge\McpSdk\TokenValidator` implements the SDK's
`AuthorizationTokenValidatorInterface`. It throws `InvalidArgumentException` when the resource is not
declared. For a valid token it returns an `AccessToken` holding the scopes the token holds right now
and these claims: `sub`, `name`, `client_id` (not for personal tokens), `aud`, `exp`, `iat` and
`subject_type` (`user` or `client`). The token value never appears in the claims. For an invalid
token it returns `unauthorized` with the code and description of
[`ValidationFailure`](protecting-resources.md).

## A complete example

Declare the MCP endpoint as a resource, with one scope per level of access:

```php
<?php
declare(strict_types=1);

use CakeDC\OAuth\Server\AuthorizationServer;
use CakeDC\OAuth\Server\Config\ServerConfig;
use CakeDC\OAuth\Server\Storage\Pdo\PdoStorage;
use Mcp\Server;
use Mcp\Server\Transport\Http\Middleware\AuthorizationMiddleware;
use Mcp\Server\Transport\Http\Middleware\CorsMiddleware;
use Mcp\Server\Transport\Http\Middleware\DnsRebindingProtectionMiddleware;
use Mcp\Server\Transport\Http\Middleware\ProtectedResourceMetadataMiddleware;
use Mcp\Server\Transport\Http\OAuth\ProtectedResourceMetadata;
use Mcp\Server\Transport\Http\OAuth\ScopePolicy;
use Mcp\Server\Transport\StreamableHttpTransport;
use Nyholm\Psr7\Factory\Psr17Factory;

require __DIR__ . '/vendor/autoload.php';

$issuer = 'https://example.com';
$mcp = 'https://example.com/mcp';
$factory = new Psr17Factory();
$pdo = new PDO('sqlite:' . __DIR__ . '/oauth.sqlite');
PdoStorage::createTables($pdo);
$users = new MyUsers($pdo); // UserProviderInterface and UserContextInterface

$oauth = new AuthorizationServer(
    ServerConfig::fromArray([
        'issuer' => $issuer,
        'secret' => getenv('OAUTH_SECRET'),
        'resources' => [
            $mcp => [
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
    ]),
    new PdoStorage($pdo),
    $users,
    $users,
    $factory,
    $factory,
);

// What the endpoint tells clients about itself, and where to find the authorization server.
$metadata = new ProtectedResourceMetadata($mcp, [$issuer], ['content:read', 'content:write', 'content:publish']);

// One scope for every request, and more for specific tools.
$policy = new ScopePolicy(
    default: ['content:read'],
    tools: ['create_draft' => ['content:write'], 'publish_post' => ['content:publish']],
    implies: ['content:publish' => ['content:write'], 'content:write' => ['content:read']],
);

$middleware = [
    new CorsMiddleware(allowedOrigins: ['https://app.example.com']), // origins of browser clients, if any
    new DnsRebindingProtectionMiddleware(['example.com']),           // the host names of this server
    new ProtectedResourceMetadataMiddleware($metadata, $factory, $factory),
    new AuthorizationMiddleware($oauth->mcpTokenValidator($mcp), $metadata, $policy, $factory, $factory),
];

$server = Server::builder()
    ->setServerInfo('Example MCP', '1.0.0')
    // ->addTool(...) your tools here
    ->build();

$transport = new StreamableHttpTransport($request, $factory, $factory, null, $middleware);
$response = $server->run($transport);
```

`$request` is the PSR-7 server request of the current call. Send the PSR-7 `$response` to the browser
the way your stack does. The authorization server's own endpoints (`/oauth/authorize`,
`/oauth/token`, the metadata and so on) are routed next to this endpoint as described in
[installation](installation.md).

### Scopes per tool

`ScopePolicy` has three ways to ask for scopes:

- `default`: scopes every request needs.
- `methods`: scopes per JSON-RPC method, for example `['tools/call' => ['content:read']]`.
- `tools`: scopes per tool name, for example `['publish_post' => ['content:publish']]`.

When a token lacks a scope the SDK answers `403 insufficient_scope` with the scopes it wants, so the
client can ask the person for more. Give `ScopePolicy` the same `implies` hierarchy as your resource,
so both sides agree about what a scope includes.

Inside a tool, the SDK's `RequestContext::getAccessToken()` gives the `AccessToken` of the request,
with the claims listed above, so a tool can know who is calling:

```php
$token = $context->getAccessToken();
$subject = $token?->getSubject();                  // the person's subject
$isService = $token?->getClaim('subject_type') === 'client';
```

## What to check in production

- The resource URL in `ServerConfig` (`$mcp`), the one in `ProtectedResourceMetadata` and the URL the
  clients type must be the same string. See [troubleshooting](troubleshooting.md#invalid_target).
- The SDK's default middleware (`StreamableHttpTransport::defaultMiddleware()`) only accepts the host
  names `localhost`, `127.0.0.1` and `[::1]`. On a real domain, every request gets `403 Forbidden:
  Invalid Host header.` until you pass your host names to `DnsRebindingProtectionMiddleware`, as in the
  example. `CorsMiddleware` lists the origins of browser clients (none by default) and already exposes
  `WWW-Authenticate`.
- Rate limiting and trusted proxies: [deployment](deployment.md).
- Connect a real client: [clients](clients.md#connecting-claudeai).
