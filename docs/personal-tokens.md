# Personal access tokens

A personal access token lets a person call your API or MCP server from a script, a CI job or a tool
that does not do OAuth. There is no client and no consent step: the person creates the token for
themselves and copies it.

Personal tokens look like `<prefix>_pat_...`. They are stored as a hash, like every token, and the
value is shown only once, when it is created.

## What they can and cannot do

- They belong to one person, one resource and a fixed set of scopes.
- They always expire. The person chooses how many days, from 1 up to `lifetimes.personalMax` (90 days by
  default).
- They have no refresh token and no client. `ValidatedToken::$client` is `null` for them.
- A person can only put scopes in a token that `UserProviderInterface::scopesFor()` lets them hold.
  Later changes to `scopesFor()` apply to existing tokens too, at the next request.
- The validation is the same as for access tokens: the owner is loaded again on every request, and the
  token stops working when `findBySubject()` returns `null`.

Turn the feature off with `'personalTokens' => false`. Existing personal tokens stop working at once
(the validator answers `Personal access tokens are disabled.`), and creating a token is refused with
`invalid_request`. The connections page still lists the person's live personal tokens and still lets
them revoke those, so people can clean up; the creation form is gone. Turning the feature on again
makes the tokens that were not revoked work again.

## Creating tokens on the connections page

The signed-in person opens `/oauth/connections`, finds "Personal access tokens", and fills in:

- a name they will recognize (up to 100 characters, with a letter, number, punctuation or symbol and no control,
  bidirectional or invisible characters),
- the resource,
- the permissions (one checkbox per scope they are allowed to give),
- the number of days (the form shows the maximum).

After "Create token" the page shows the token once, with a warning to copy it. The page does not show
it again. See [pages](pages.md) for the form fields if you replace the page.

## Creating tokens from code

`ConnectionService::createPersonalToken()` does the same work, with the same checks:

```php
use CakeDC\OAuth\Server\Exception\OAuthException;

$owner = $users->findBySubject('42');

try {
    $created = $server->connectionService()->createPersonalToken(
        owner: $owner,
        name: 'CI deploy',
        resource: 'https://example.com/api',
        scopes: ['read'],
        days: 30,
    );
} catch (OAuthException $e) {
    // invalid_request, invalid_target or invalid_scope, with a message for the person
    throw $e;
}

echo $created['value']; // oauth_pat_..., show it once
// $created['token'] is the stored Token (id, name, scopes, expiresAt...)
```

`createPersonalToken(ResourceOwner $owner, string $name, string $resource, array $scopes, int $days):
array` returns `['token' => Token, 'value' => string]`.

It throws `OAuthException` with:

| Code | When |
| --- | --- |
| `invalid_request` | The owner is not a person (`SubjectType::Client`), the name is empty, too long or has control characters, or `days` is outside 1 to the maximum |
| `invalid_target` | The resource is not declared |
| `invalid_scope` | No scope given, or a scope the person may not give (`You cannot grant "..."`) |

To show a form you can ask what a person may create:

- `$server->connectionService()->creatableScopes($owner)`: `resource => ['name' => ..., 'scopes' => [scope => description]]`.
- `$server->connectionService()->maxPersonalDays()`: the longest life in days (`personalMax` divided by 86400, at least 1).

A `TokenIssued` event is dispatched with a `null` client. See [events](events.md).

## Limits

`lifetimes.personalMax` caps the life of every personal token (default `7776000` seconds, 90 days):

```php
'lifetimes' => ['personalMax' => 2592000], // 30 days
```

There is no limit on how many tokens a person has. If you need one, count with
`$server->connectionService()->personalTokens($owner)` before you create.

## Listing and revoking

```php
$tokens = $server->connectionService()->personalTokens($owner); // live tokens, oldest first

$revoked = $server->connectionService()->revokePersonalToken($owner, $tokens[0]->id); // bool
```

`revokePersonalToken()` returns `false` when the token is not the person's own, so a person cannot
revoke someone else's token by guessing an id. It dispatches `TokenRevoked` with the reason `personal`.

The `/oauth/revoke` endpoint does not revoke personal tokens, because it needs a client. People revoke
them on the connections page. Administrators can use `TokenRevoker::revokeAllForSubject()`, which
revokes personal tokens too ([operations](operations.md)).

## Using a personal token

Send it like any access token:

```bash
curl -H "Authorization: Bearer oauth_pat_..." https://example.com/api/me
```

Your resource must be protected with [`BearerTokenMiddleware`](protecting-resources.md) or
`TokenValidator`. Personal tokens are valid only for the resource they were created for.
A personal token presented to the introspection endpoint answers `active: true` without a
`client_id`.
