# Operations

Everyday tasks for the people who run the server.

## Pruning

Expired and revoked rows pile up. `Pruner` deletes what is no longer needed. Run it from cron, once a
day is enough.

`bin/oauth-prune.php` in your application:

```php
<?php
declare(strict_types=1);

// Build the same $server as in your web entry point.
$server = require __DIR__ . '/../config/oauth.php';

$result = $server->pruner()->prune();

printf(
    "Pruned %d codes, %d tokens, %d clients.\n",
    $result->codes,
    $result->tokens,
    $result->clients,
);
```

```cron
15 3 * * * php /var/www/app/bin/oauth-prune.php >> /var/log/oauth-prune.log 2>&1
```

`$server->pruner()` uses `retentionDays` from the configuration. You can build one by hand:

```php
use CakeDC\OAuth\Server\Maintenance\Pruner;

$pruner = new Pruner($server->storage(), $server->clock(), retentionDays: 14, unusedClientSeconds: 86400);
```

What `prune()` deletes:

| Rows | Condition |
| --- | --- |
| Authorization codes | Expired |
| Tokens | Revoked, or expired, more than `retentionDays` ago (default 7 days) |
| Clients | Dynamic or metadata document clients created more than `unusedClientSeconds` ago (24 hours), unused for `retentionDays`, and without live tokens. Their codes, tokens and consents go with them. Registered clients are never deleted |

`PruneResult` has `codes`, `tokens` and `clients`, counting cascaded rows as well.

A pruned dynamic client is gone. If its program comes back it gets `invalid_client` and must register
again, which well-behaved clients do. A pruned metadata document client is fetched again at the next
request, so nobody notices.

## Revoking a leaked token

If a token leaked, revoke its whole family so that the refresh token dies with it:

```php
use CakeDC\OAuth\Server\Token\TokenGenerator;

$token = $server->storage()->findTokenByHash(TokenGenerator::hash($leakedValue));
if ($token !== null) {
    $server->tokenRevoker()->revokeFamily($token->familyId, 'leaked', $token);
}
```

`revokeFamily(string $familyId, string $reason, ?Token $token = null): int` returns how many tokens it
revoked and dispatches `TokenRevoked` with your reason. The reason is free text for your logs.

For a personal token, or one access token only:

```php
$server->tokenRevoker()->revokeTokens([$token], 'leaked', $token);
```

The client of a token can revoke it too, through the [`/revoke` endpoint](endpoints.md#post-oauthrevoke).

## Revoking everything of a person

After a password change, a suspected account takeover, or when someone leaves:

```php
$count = $server->tokenRevoker()->revokeAllForSubject('42'); // access, refresh and personal tokens
```

Their connections stop working at once. If the person should be asked again, also forget their
consents. Consents are per client and resource:

```php
$server->consentService()->forget('42', $client->id, 'https://example.com/mcp');
```

You do not need to revoke when you deactivate the account: `findBySubject()` returning `null` already
cuts every token. Revoking is still the right thing when the account is deleted for good, so no rows
wait for reactivation.

Revoke after a policy change too (`canAuthorize()` is not asked again after `/authorize`).

## Revoking a client

To cut a client off completely and for good (it can no longer authenticate, authorize or refresh):

```php
$client = $server->storage()->findClientByClientId($clientId);
if ($client !== null) {
    $server->storage()->saveClient($client->withRevokedAt($server->clock()->now()));
    $server->tokenRevoker()->revokeAllForClient($client);
}
```

Revocation of a client is permanent in storage: `saveClient()` never clears `revokedAt`, so a metadata
refresh or a stale copy cannot bring the client back. Its tokens are rejected at once
(`The client of this access token was revoked.`).

To revoke all tokens of a client but let it work again, call `revokeAllForClient()` alone.

## Rotating the secret

The `secret` setting signs the consent and connections forms and nothing else. Tokens are random and
do not depend on it. To rotate it, deploy the new value.

Forms that were open at that moment stop working. A person who submits one sees an error ("The consent
form expired or was changed. Start again from the application.") and starts over. Forms are valid for 15
minutes anyway, so choose a quiet moment. Existing tokens, codes and connections are not affected.
There is no support for two secrets at once.

## Monitoring with events

Wire a PSR-14 dispatcher ([events](events.md)) and watch these:

| Signal | Why it matters |
| --- | --- |
| `RefreshTokenReused` rising | Possible token theft, or a buggy client that refreshes in parallel |
| `TokenRevoked` with `code_reuse` | A code was replayed. Often an attack, sometimes a double click |
| `AuthorizationDenied` with `not_allowed` | People blocked by `canAuthorize()`. Check your policy |
| `ClientRegistered` bursts | Someone is filling registration. Consider `token` mode |
| HTTP `429` from the endpoints | Rate limits hit. Either an abuser or limits that are too low for a shared address range |
| `server_error` in your log | A bug or a database problem. The responses never show details, the log does |

The built-in logger calls use a PSR-3 `LoggerInterface`. Pass yours as `logger` to see them.

## Backups

Back up the four tables like the rest of your database. Tokens are hashes, so a backup does not
contain usable tokens. Restoring an old backup brings back tokens and consents that were revoked
after it was taken, so revoke again what you must after a restore.
