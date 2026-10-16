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
| Clients | Dynamic or metadata document clients created more than `unusedClientSeconds` ago (24 hours), unused for `retentionDays`, and without live tokens. Their codes, tokens and consents go with them. Registered clients and revoked clients are never deleted |

`PruneResult` has `codes`, `tokens` and `clients`, counting cascaded rows as well.

A client is deleted only if it is still unused when its turn comes. `PdoStorage` selects the
candidates, then deletes each one in its own transaction that starts with a conditional claim (one
`UPDATE` that repeats the conditions above), and deletes the client's rows only when the claim took it.
So a client that a request used after the selection (a recorded use, or a new live token) is kept. On
MySQL and PostgreSQL the client row is locked first, so a request inserting a token for it at that moment
is waited for. On SQLite, turn foreign keys on for the connection (`PRAGMA foreign_keys = ON`): without
them a token saved just after its client was pruned is stored as an orphan instead of being refused.

A revoked client stays as a tombstone, whatever its type: its row is what keeps the revocation sticky,
because a pruned revoked metadata document client would be fetched again and come back to life. Its tokens, codes and
consents are still pruned by the normal rules.

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

Their connections stop working at once. The person's authorization codes that were not exchanged yet
are deleted too, so a code issued a moment before cannot open a new connection afterwards. End the
person's sessions in your application first, so that no new code is issued while you revoke.

If the person should be asked again, also forget their consents. Consents are per client and resource:

```php
$server->consentService()->forget('42', $client->id, 'https://example.com/mcp');
```

### Cutting a person off completely

`revokeAllForSubject()` never deletes consents (only tokens and codes not exchanged yet). To remove a person
completely, so that even a new authorization request has to start from scratch, do both:

```php
$server->tokenRevoker()->revokeAllForSubject('42');
$deleted = $server->storage()->deleteConsentsBySubject('42'); // how many consents were removed
```

`$server->storage()->findConsentsBySubject('42')` lists what is there first (oldest first), for example
for an export. The subject is compared exactly, including its case.

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
(`The client of this access token was revoked.`), and `revokeAllForClient()` also deletes its codes that
were not exchanged yet. Pruning never deletes a revoked client, so the revocation also survives the daily
prune.

To revoke all tokens of a client but let it work again, call `revokeAllForClient()` alone.

### Undoing a client revocation

The library never clears a revocation, on purpose. For a dynamic client that is usually fine: its program
registers again and gets a new `client_id`. A metadata document client cannot do that, because its
`client_id` is the fixed URL of its document. Revoking `https://claude.ai/oauth/mcp-oauth-client-metadata`
cuts claude.ai off for every person, for good, until somebody changes the row by hand.

To block a metadata document client for a while, prefer a switch you can turn back:

- `cimd.allowedHosts` lists the hosts whose clients are accepted, and it applies to stored rows too:
  remove a host and its clients are refused at the next request (no fetch, no new code, no refresh); put
  it back and they work again. The list is an allow list, so this suits servers that already list their
  hosts (for example `['claude.ai']`). `cimd.enabled => false` turns every metadata document client off.
- Access tokens already issued stay valid until they expire (an hour by default). To end them at once,
  call `revokeAllForClient($client)` without revoking the client: the people connect again once the host
  is allowed again.

To undo a revocation that was already made, edit the row in your database, for example:

```sql
-- Bring the client back. Its tokens stay revoked, so people connect again.
UPDATE oauth_clients SET revoked_at = NULL
WHERE client_id = 'https://claude.ai/oauth/mcp-oauth-client-metadata';

-- Or forget the row completely: the next request fetches the document again and stores a new row.
-- Its codes, tokens and consents go with it (ON DELETE CASCADE; on SQLite only with foreign keys on).
DELETE FROM oauth_clients
WHERE client_id = 'https://claude.ai/oauth/mcp-oauth-client-metadata';
```

Use your table prefix if it is not `oauth_`. Run either one only when you mean it: the revocation was
probably made for a reason, and nothing in the library will make it again.

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
| Warning `Rate limiting is off for this request: the cache failed` | Your PSR-16 cache is down. The endpoints keep working, but nothing is rate limited until it is back |

The built-in logger calls use a PSR-3 `LoggerInterface`. Pass yours as `logger` to see them.

## Backups

Back up the four tables like the rest of your database. Tokens are hashes, so a backup does not
contain usable tokens. Restoring an old backup brings back tokens and consents that were revoked
after it was taken, so revoke again what you must after a restore.
