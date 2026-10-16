# Users

The server does not know your people. You tell it about them with two interfaces:

- `UserProviderInterface` answers questions about people: who is this, may they do that, which scopes
  do they hold.
- `UserContextInterface` ties the server to your login: who is signed in right now, and how to send
  a visitor to the login page.

One class can implement both, as `examples/standalone/DemoUsers.php` does.

## `ResourceOwner`

Both interfaces speak in `ResourceOwner` objects:

```php
new ResourceOwner(
    subject: '42',              // stable id, stored with grants and tokens
    displayName: 'Ada Lovelace', // shown on the consent and connections pages
    identity: $userEntity,       // your own object, never touched by the server
    type: SubjectType::User,     // SubjectType::User (default) or SubjectType::Client
);
```

- `subject` is a stable string of up to 255 characters, for example the primary key. It is stored in
  the database and compared case-sensitively. Never use something that changes (an email address
  that can be edited).
- `displayName` is shown to the person and appears as `name` in the MCP claims and as `username` in
  introspection responses.
- `identity` is yours. Read it back in your handlers with
  `$request->getAttribute(ResourceOwner::class)->identity`.
- `type` keeps people and clients apart, so a client whose id equals a user's subject can never act as
  that user. Use `SubjectType::Client` for the owner you return from `forClient()`.

## `UserProviderInterface`

| Method | Called | Returns |
| --- | --- | --- |
| `findBySubject(string $subject): ?ResourceOwner` | On every protected request, on code exchange, on refresh | The person, or `null` when they are gone or no longer active |
| `canAuthorize(ResourceOwner $owner, Client $client, ProtectedResource $resource): bool` | At `/authorize` | Whether this person may let this client act on this resource |
| `scopesFor(ResourceOwner $owner, ProtectedResource $resource): ?array` | At consent, at refresh and on every protected request | The scopes the person may hold on the resource, or `null` for all of them |
| `forClient(Client $client, ProtectedResource $resource): ?ResourceOwner` | For the client credentials grant, and when such a token is used | The identity the client acts as, or `null` to refuse |

### `findBySubject`

This runs on every request that presents a token, so make it fast (a primary key lookup, or a short
cache). Returning `null` cuts access at once: the person's tokens stop working on their next call, and
refresh is refused. Return `null` for deleted and deactivated people. If you return the person again
later (reactivation), their existing connections work again without a new consent.

### `canAuthorize`

Use it for rules such as "only staff may connect to the admin API". When it returns `false` the
client receives `access_denied` and an `AuthorizationDenied` event with the reason `not_allowed` is
dispatched.

The library asks only at `/authorize`. If your rule changes afterwards, revoke the person's tokens
yourself:

```php
$server->tokenRevoker()->revokeAllForSubject($subject);
```

### `scopesFor`

Return the list of scopes this person may hold on the resource, or `null` for every scope the
resource declares. The list may name implying scopes: a person with `['content:publish']` also holds
what `content:publish` implies.

The answer is checked when the person approves and again on every request, so a role change applies
immediately. A person who loses a scope loses it on all existing tokens.

```php
public function scopesFor(ResourceOwner $owner, ProtectedResource $resource): ?array
{
    return $owner->identity['role'] === 'editor' ? ['content:read', 'content:write'] : null;
}
```

### `forClient`

Only needed for the client credentials grant (machine to machine). Return the identity the client acts
as, for example a service account, or `null` to refuse the grant:

```php
public function forClient(Client $client, ProtectedResource $resource): ?ResourceOwner
{
    return $client->name === 'Nightly import'
        ? new ResourceOwner('service:import', 'Nightly import', null, SubjectType::Client)
        : null;
}
```

If you never use client credentials return `null` and set `'clientCredentials' => false`. The token's
subject is the client's `client_id` and its type is `client`. `scopesFor()` is called with the owner
you return here. See [clients](clients.md#client-credentials).

## `UserContextInterface`

| Method | Purpose |
| --- | --- |
| `currentOwner(ServerRequestInterface $request): ?ResourceOwner` | The signed-in person of this browser request, or `null` |
| `loginResponse(ServerRequestInterface $request, string $returnTo): ResponseInterface` | The response that sends a visitor to your login |

`loginResponse()` receives `$returnTo`, a relative URL (a path and a query, like
`/oauth/authorize?response_type=code&...`). The server has already normalised it with
`RequestPath::safe()`: one leading slash (so it can never read as `//host`), and a request path with
control characters or backslashes is refused. The same path is used as the `action` of the built-in forms. Your login page must send the person back to it after sign-in.

Validate it again before you redirect, so your own login page is not an open redirect. This is the
check from `examples/standalone/LocalPath.php`:

```php
$safe = preg_match('#\A/(?![/\\\\])[^\x00-\x1F\x7F\\\\]*\z#', $return) === 1 ? $return : '/';
```

The login must share its session with the authorize path. If your session cookie is limited to a
path that does not include `/oauth/`, the person signs in and the server still sees nobody. Use
`path=/` (see [troubleshooting](troubleshooting.md#login-loops)).

Use `SameSite=Lax` cookies. The authorize page is reached by a top-level redirect from the client,
which `Lax` allows, and the consent form is also protected by a signed form token.

## A complete example

PDO users table, PHP sessions, roles that map to scopes:

```php
<?php
declare(strict_types=1);

namespace App\OAuth;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Owner\UserContextInterface;
use CakeDC\OAuth\Server\Owner\UserProviderInterface;
use CakeDC\OAuth\Server\Resource\ProtectedResource;
use Nyholm\Psr7\Response;
use PDO;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class MyUsers implements UserProviderInterface, UserContextInterface
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    public function findBySubject(string $subject): ?ResourceOwner
    {
        $statement = $this->pdo->prepare('SELECT id, name, role FROM users WHERE id = ? AND active = 1');
        $statement->execute([$subject]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if ($row === false) {
            return null;
        }

        return new ResourceOwner((string)$row['id'], (string)$row['name'], $row);
    }

    public function canAuthorize(ResourceOwner $owner, Client $client, ProtectedResource $resource): bool
    {
        return true;
    }

    public function scopesFor(ResourceOwner $owner, ProtectedResource $resource): ?array
    {
        // Viewers may read, everybody else may hold every scope.
        return ($owner->identity['role'] ?? '') === 'viewer' ? ['content:read'] : null;
    }

    public function forClient(Client $client, ProtectedResource $resource): ?ResourceOwner
    {
        return null;
    }

    public function currentOwner(ServerRequestInterface $request): ?ResourceOwner
    {
        $subject = $_SESSION['user_id'] ?? null;

        return is_string($subject) ? $this->findBySubject($subject) : null;
    }

    public function loginResponse(ServerRequestInterface $request, string $returnTo): ResponseInterface
    {
        return new Response(302, ['Location' => '/login?return=' . rawurlencode($returnTo)]);
    }
}
```

Your `/login` action signs the person in, regenerates the session id (so an id planted before login
is worthless) and redirects to the validated `return` value.

If your framework has its own authentication, `currentOwner()` reads the identity from it (the
request attribute your auth middleware sets, for example) and `loginResponse()` redirects to your
login route. See [frameworks](frameworks.md).

## Display names

`displayName` is shown on the consent page ("Signed in as Ada Lovelace.") and on the connections page.
The library escapes it for HTML. Your own renderers must do the same. See [pages](pages.md).
