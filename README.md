# CakeDC OAuth Server

An OAuth 2.1 authorization server for any PHP application, ready for MCP servers.

It is a library, not a framework. It speaks PSR-7 and PSR-15, keeps its data through a small storage
interface, and leaves your login and your users to you. You get a set of request handlers, one per
endpoint, and route them in the framework you already use.

## Features

- OAuth 2.1 authorization code flow with PKCE (S256 only, mandatory for every client)
- Refresh tokens with rotation and reuse detection, and a configurable grace window for lost responses
- Client credentials grant for service to service calls
- Three ways to know a client: Client ID Metadata Documents (CIMD, preferred), dynamic client
  registration (RFC 7591) and clients you register by hand
- Resource indicators (RFC 8707): every token is bound to one resource
- The `iss` parameter on authorization responses (RFC 9207)
- Authorization server metadata (RFC 8414)
- Token revocation (RFC 7009) and introspection (RFC 7662)
- A consent page and a connections page where people see and revoke what they connected
- Personal access tokens for scripts
- Scopes with hierarchies, checked on every request, so role changes apply at once
- Storage on PDO (SQLite, MySQL/MariaDB, PostgreSQL), an in-memory storage for tests and a contract test
  for your own storage
- PSR-15 middleware to protect your routes, and a bridge for the official MCP PHP SDK
- PSR-14 events for audit logs, rate limiting through any PSR-16 cache, and a pruning job
- Checked against the official MCP conformance suite for authorization servers

## Requirements

- PHP 8.2 or newer
- A PSR-17 implementation, for example `nyholm/psr7`
- `ext-pdo` for `PdoStorage` and `ext-curl` for Client ID Metadata Documents (both optional)

## Install

```bash
composer require cakedc/oauth-server nyholm/psr7
```

## Five-minute start

This is the shape of every integration. `examples/standalone/` is a complete, runnable version of it
(`php -S 127.0.0.1:8090 examples/standalone/server.php`, see its README).

**1. Create the tables.**

```php
use CakeDC\OAuth\Server\Storage\Pdo\PdoStorage;

$pdo = new PDO('sqlite:' . __DIR__ . '/oauth.sqlite');
PdoStorage::createTables($pdo);
```

**2. Tell the server about your people.** Implement `UserProviderInterface` (who exists, what they may
do) and `UserContextInterface` (who is signed in, how to send a visitor to the login). One class can do
both:

```php
use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Owner\UserContextInterface;
use CakeDC\OAuth\Server\Owner\UserProviderInterface;
use CakeDC\OAuth\Server\Resource\ProtectedResource;
use Nyholm\Psr7\Response;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class MyUsers implements UserProviderInterface, UserContextInterface
{
    private const PEOPLE = ['1' => 'Ada', '2' => 'Grace'];

    public function findBySubject(string $subject): ?ResourceOwner
    {
        return isset(self::PEOPLE[$subject]) ? new ResourceOwner($subject, self::PEOPLE[$subject]) : null;
    }

    public function canAuthorize(ResourceOwner $owner, Client $client, ProtectedResource $resource): bool
    {
        return true;
    }

    public function scopesFor(ResourceOwner $owner, ProtectedResource $resource): ?array
    {
        return null; // every scope of the resource
    }

    public function forClient(Client $client, ProtectedResource $resource): ?ResourceOwner
    {
        return null; // no client credentials
    }

    public function currentOwner(ServerRequestInterface $request): ?ResourceOwner
    {
        $subject = $_SESSION['user'] ?? null;

        return is_string($subject) ? $this->findBySubject($subject) : null;
    }

    public function loginResponse(ServerRequestInterface $request, string $returnTo): ResponseInterface
    {
        return new Response(302, ['Location' => '/login?return=' . rawurlencode($returnTo)]);
    }
}
```

**3. Build the server.**

```php
use CakeDC\OAuth\Server\AuthorizationServer;
use CakeDC\OAuth\Server\Config\ServerConfig;
use Nyholm\Psr7\Factory\Psr17Factory;

$factory = new Psr17Factory();
$users = new MyUsers();

$server = new AuthorizationServer(
    ServerConfig::fromArray([
        'issuer' => 'https://auth.example.com',
        'secret' => getenv('OAUTH_SECRET'), // at least 32 characters (for example 32 random bytes, hex or base64 encoded)
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
    $users,
    $users,
    $factory,
    $factory,
);
```

**4. Route the handlers.** Each endpoint is a PSR-15 request handler. This is the routing of
`examples/standalone/server.php`:

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
    default => $yourApplication->handle($request),
};
```

**5. Protect a route.**

```php
$protected = $server->bearerMiddleware('https://auth.example.com/api', requiredScopes: ['read']);
$response = $protected->process($request, $yourApiHandler);
```

Your handler finds the person in `$request->getAttribute(ResourceOwner::class)`.

## Documentation

Start with [docs/index.md](docs/index.md). All pages:

| Page | What it covers |
| --- | --- |
| [docs/index.md](docs/index.md) | Table of contents |
| [docs/concepts.md](docs/concepts.md) | OAuth in plain words, and the authorization code flow |
| [docs/installation.md](docs/installation.md) | Requirements, tables, first configuration, routing |
| [docs/configuration.md](docs/configuration.md) | Every setting, with defaults |
| [docs/users.md](docs/users.md) | Connecting your people and your login |
| [docs/storage.md](docs/storage.md) | Storages, writing your own, the schema |
| [docs/endpoints.md](docs/endpoints.md) | The HTTP reference |
| [docs/errors.md](docs/errors.md) | Every error code and what to do |
| [docs/protecting-resources.md](docs/protecting-resources.md) | Bearer middleware and token validation |
| [docs/mcp.md](docs/mcp.md) | Using it with the official MCP PHP SDK |
| [docs/frameworks.md](docs/frameworks.md) | Plain PHP, Slim, Mezzio, Symfony, Laravel |
| [docs/clients.md](docs/clients.md) | Client types, registration, claude.ai, Claude Code and others |
| [docs/pages.md](docs/pages.md) | The consent and connections pages, custom renderers, translation |
| [docs/personal-tokens.md](docs/personal-tokens.md) | Personal access tokens |
| [docs/events.md](docs/events.md) | PSR-14 events and an audit log |
| [docs/security.md](docs/security.md) | Threat model, RFC 9700, production checklist |
| [docs/deployment.md](docs/deployment.md) | Proxies, nginx, Apache, Cloudflare, CORS |
| [docs/operations.md](docs/operations.md) | Pruning, revocation, secret rotation, monitoring |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Symptoms, causes and fixes |
| [docs/conformance.md](docs/conformance.md) | The MCP conformance run (`tests/Conformance/run.sh`) |

## CakePHP

CakePHP applications should use the plugin [`cakedc/cakephp-oauth-server`](https://github.com/CakeDC/cakephp-oauth-server),
which wraps this library with CakePHP routing, authentication, views and migrations. This package is
the framework-agnostic core.

## Tests

```bash
composer install
composer check   # phpunit, phpcs and phpstan
```

The storage tests for MySQL and PostgreSQL run when `OAUTH_TEST_MYSQL_DSN` and `OAUTH_TEST_PGSQL_DSN`
are set. The conformance run is described in [docs/conformance.md](docs/conformance.md).

## License

MIT. See [LICENSE](LICENSE).
