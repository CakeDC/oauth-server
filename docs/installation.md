# Installation

## Requirements

- PHP 8.2 or newer.
- A PSR-17 implementation (response and stream factories), for example `nyholm/psr7` or
  `laminas/laminas-diactoros`. The server builds PSR-7 responses with them.
- `ext-pdo` with a driver (SQLite, MySQL/MariaDB or PostgreSQL) if you use `PdoStorage`.
- `ext-curl` if you accept Client ID Metadata Documents (the default). Without it, either pass your
  own `HttpTransportInterface` to `AuthorizationServer` or set `cimd.enabled` to `false`.
- Optional: `mcp/sdk`, only for `mcpTokenValidator()`. See [MCP](mcp.md).

The library has no mbstring dependency.

## Install

```bash
composer require cakedc/oauth-server nyholm/psr7
```

## Create the tables

`PdoStorage` uses four tables: `oauth_clients`, `oauth_authorization_codes`, `oauth_tokens` and
`oauth_consents`. The simplest way to create them is from PHP:

```php
use CakeDC\OAuth\Server\Storage\Pdo\PdoStorage;

$pdo = new PDO('sqlite:/var/lib/myapp/oauth.sqlite');
PdoStorage::createTables($pdo);
```

`createTables(PDO $pdo, string $tablePrefix = 'oauth_')` picks the file in `schema/` from the PDO driver
name and runs it. It uses `CREATE TABLE IF NOT EXISTS`, so it is safe to call again. If you use a
table prefix other than `oauth_`, pass the same prefix to `new PdoStorage($pdo, $prefix)`.

If you prefer to run SQL yourself (a migration tool, for example), use the files directly:

| Database | File |
| --- | --- |
| SQLite | `schema/sqlite.sql` |
| MySQL, MariaDB | `schema/mysql.sql` |
| PostgreSQL | `schema/pgsql.sql` |

MySQL tables use `utf8mb4` with the binary collation `utf8mb4_bin`, so subjects and ids compare
case-sensitively. Open your MySQL connection with `charset=utf8mb4` in the DSN. See
[storage](storage.md) for every column.

## First configuration

You need two interfaces from your application: [`UserProviderInterface` and
`UserContextInterface`](users.md). This example assumes a class `MyUsers` that implements both.

```php
<?php
declare(strict_types=1);

use CakeDC\OAuth\Server\AuthorizationServer;
use CakeDC\OAuth\Server\Config\ServerConfig;
use CakeDC\OAuth\Server\Storage\Pdo\PdoStorage;
use Nyholm\Psr7\Factory\Psr17Factory;

require __DIR__ . '/vendor/autoload.php';

$pdo = new PDO('sqlite:' . __DIR__ . '/oauth.sqlite');
PdoStorage::createTables($pdo);
$users = new MyUsers($pdo);
$factory = new Psr17Factory();

$server = new AuthorizationServer(
    ServerConfig::fromArray([
        'issuer' => 'https://auth.example.com',
        // At least 32 random bytes. Keep it out of version control.
        'secret' => getenv('OAUTH_SECRET'),
        'resources' => [
            'https://auth.example.com/api' => [
                'name' => 'Example API',
                'scopes' => ['read' => 'Read your profile', 'write' => 'Change your profile'],
                'implies' => ['write' => ['read']],
                'defaultScopes' => ['read'],
            ],
        ],
    ]),
    new PdoStorage($pdo),
    $users,   // UserProviderInterface
    $users,   // UserContextInterface
    $factory, // ResponseFactoryInterface
    $factory, // StreamFactoryInterface
);
```

Generate a secret once with `php -r 'echo bin2hex(random_bytes(32)), PHP_EOL;'` and keep it in the
environment. All settings are listed in [configuration](configuration.md).

The constructor takes more optional arguments: an event dispatcher (`$events`), a PSR-16 cache
for rate limiting (`$cache`), a PSR-20 clock, a PSR-3 logger, a CIMD transport and DNS resolver,
`Messages`, custom page renderers and a `$clientIp` closure. They are covered where they matter
([events](events.md), [security](security.md), [pages](pages.md), [deployment](deployment.md)).

## Route the endpoints

The server gives you one PSR-15 request handler per endpoint. You decide how requests reach them.
Compare the request path with the paths the configuration computes:

| Handler | Path | Methods |
| --- | --- | --- |
| `metadataHandler()` | `$config->metadataPath()` | GET, OPTIONS |
| `authorizeHandler()` | `$config->endpointPath('authorize')` | GET, POST |
| `tokenHandler()` | `$config->endpointPath('token')` | POST, OPTIONS |
| `registerHandler()` | `$config->endpointPath('register')` | POST, OPTIONS |
| `revokeHandler()` | `$config->endpointPath('revoke')` | POST, OPTIONS |
| `introspectHandler()` | `$config->endpointPath('introspect')` | POST, OPTIONS |
| `connectionsHandler()` | `$config->endpointPath('connections')` | GET, POST |

With the default `routePrefix` of `/oauth` and the issuer above the paths are
`/.well-known/oauth-authorization-server`, `/oauth/authorize`, `/oauth/token`, `/oauth/register`,
`/oauth/revoke`, `/oauth/introspect` and `/oauth/connections`. If the issuer has a path, for example
`https://example.com/auth`, the metadata path is
`/.well-known/oauth-authorization-server/auth` and the endpoints live below `/auth/oauth/`.

`$config->endpointUrl('token')` and `$config->metadataUrl()` give the absolute URLs.

A minimal front controller, adapted from `examples/standalone/server.php`:

```php
$config = $server->config();
$path = $request->getUri()->getPath();

$response = match (true) {
    $path === $config->metadataPath() => $server->metadataHandler()->handle($request),
    $path === $config->endpointPath('authorize') => $server->authorizeHandler()->handle($request),
    $path === $config->endpointPath('token') => $server->tokenHandler()->handle($request),
    $path === $config->endpointPath('register') => $server->registerHandler()->handle($request),
    $path === $config->endpointPath('revoke') => $server->revokeHandler()->handle($request),
    $path === $config->endpointPath('introspect') => $server->introspectHandler()->handle($request),
    $path === $config->endpointPath('connections') => $server->connectionsHandler()->handle($request),
    $path === '/api/me' => $server->bearerMiddleware('https://auth.example.com/api')->process($request, $me),
    default => new Nyholm\Psr7\Response(404),
};
```

`$request` is a PSR-7 `ServerRequestInterface`. Build it from the PHP globals with your PSR-7
implementation (see `examples/standalone/server.php`) or let your framework do it
([frameworks](frameworks.md)).

Then check the discovery document:

```bash
curl -s https://auth.example.com/.well-known/oauth-authorization-server
```

You can try everything locally with the example in `examples/standalone/README.md`.

## Next steps

- [Users](users.md): connect your login and your permissions.
- [Clients](clients.md): register a client or connect Claude.
- [Security](security.md) and [deployment](deployment.md) before you go to production.
