# Storage

The server keeps clients, authorization codes, tokens and consents in a storage you choose.

## `StorageInterface`

`StorageInterface` is the union of five smaller interfaces. A class may implement all of them, as
`PdoStorage` and `InMemoryStorage` do.

| Interface | Stores | Methods |
| --- | --- | --- |
| `ClientRepositoryInterface` | Clients | `findClientByClientId`, `findClientById`, `saveClient`, `touchClient`, `findClients` |
| `AuthorizationCodeRepositoryInterface` | Codes | `saveCode`, `findCodeByHash`, `consumeCode` |
| `TokenRepositoryInterface` | Access, refresh and personal tokens | `saveToken`, `findTokenByHash`, `findTokenById`, `markTokenUsed`, `revokeToken`, `revokeTokenFamily`, `revokeTokensBySubject`, `revokeTokensByClient`, `findTokensByFamily`, `findActiveTokensBySubject`, `touchToken` |
| `ConsentRepositoryInterface` | Consents | `findConsent`, `saveConsent`, `deleteConsent`, `findConsentsBySubject`, `deleteConsentsBySubject` |
| `MaintenanceInterface` | Housekeeping | `prune` |

Tokens, codes and client secrets are only ever stored as SHA-256 hashes. The raw value exists only
in the response that creates it.

## `PdoStorage`

```php
use CakeDC\OAuth\Server\Storage\Pdo\PdoStorage;

$pdo = new PDO('mysql:host=127.0.0.1;dbname=app;charset=utf8mb4', $user, $password);
PdoStorage::createTables($pdo);            // once, or from a migration
$storage = new PdoStorage($pdo);           // prefix 'oauth_'
```

- `new PdoStorage(PDO $pdo, string $tablePrefix = 'oauth_')`. The prefix may contain lowercase letters,
  digits and `_`. The storage switches the connection to `PDO::ERRMODE_EXCEPTION`.
- `PdoStorage::createTables(PDO $pdo, string $tablePrefix = 'oauth_')` runs the schema file that
  matches the driver (`sqlite`, `mysql` or `pgsql`). It throws `RuntimeException` for another driver.
  With a custom prefix, table, index and constraint names get the prefix, and the column
  `oauth_client_id` keeps its name.
- On MySQL use a DSN with `charset=utf8mb4`. Consider `PDO::ATTR_EMULATE_PREPARES => false`.
- On SQLite the `REFERENCES` clauses are only enforced with `PRAGMA foreign_keys = ON`. Pruning deletes
  child rows explicitly, so it works either way.
- Dates are stored in UTC.

## `InMemoryStorage`

```php
use CakeDC\OAuth\Server\Storage\InMemory\InMemoryStorage;

$storage = new InMemoryStorage();
```

Everything lives in PHP arrays and disappears at the end of the request. Use it in tests. It is not
safe for production: nothing is shared between processes.

The testing helpers `CakeDC\OAuth\Server\Testing\ArrayCache` (a PSR-16 cache for rate limiting) and
`FrozenClock` (a PSR-20 clock you can move) are meant for tests too.

## Writing your own storage

Implement `StorageInterface` (for example on Doctrine, Eloquent or a document database). Then prove
it works by running the contract test against it. `StorageContractTestCase` ships in the package
(`CakeDC\OAuth\Server\Testing`) and needs PHPUnit in your dev dependencies.

```php
<?php
declare(strict_types=1);

namespace App\Test\TestCase;

use App\OAuth\DoctrineStorage;
use CakeDC\OAuth\Server\Storage\StorageInterface;
use CakeDC\OAuth\Server\Testing\StorageContractTestCase;

class DoctrineStorageTest extends StorageContractTestCase
{
    protected function createStorage(): StorageInterface
    {
        $storage = new DoctrineStorage(/* a test connection */);
        $storage->truncateEverything(); // the contract needs an empty storage each time

        return $storage;
    }
}
```

Run it with `vendor/bin/phpunit`. The contract pins the behaviour below. If a test fails, the
storage would have a security bug in production.

### Atomic operations and why they matter

| Operation | Rule | Why |
| --- | --- | --- |
| `consumeCode($id, $at, $familyId)` | Marks the code used and records the family, in one step. Of two concurrent calls only one returns `true` | A code must work once, even when two requests race |
| `markTokenUsed($id, $at)` | Marks a refresh token used in one step; `true` for one caller only. A revoked token is never marked (`false`) | Refresh rotation must have one winner, and a revocation beats a rotation in flight |
| `revokeToken`, `revokeTokenFamily`, `revokeTokensBySubject`, `revokeTokensByClient` | Only change rows that are not revoked yet, and return how many they changed | Counts in events must be exact, and the first revocation time must not be overwritten |
| `saveClient` | Inserts or updates by internal id. Never clears a stored `revokedAt` | Revocation is permanent. A stale copy of a client must not undo it |
| `saveConsent` | Inserts, or replaces the scopes of the consent with the same subject, client and resource, keeping its id and creation time | One consent per subject, client and resource |
| `findConsentsBySubject`, `deleteConsentsBySubject` | List (oldest first) and delete every consent of one subject, comparing the subject exactly (`Alice` is not `alice`). The delete returns how many it removed | Removing a person completely, for example when an account is deleted |
| `prune` | Deletes in the way described in [operations](operations.md) and returns a `PruneResult` that counts cascaded rows too | Housekeeping must not leave orphans |

Other rules the contract pins:

- Malformed or unknown ids return `null`, `false`, `0` or `[]`. They never throw.
- Subjects compare case-sensitively (`'Ada'` and `'ada'` are two people). MySQL tables use
  `utf8mb4_bin` for this.
- Client ids can be long URLs, up to 2048 characters. `PdoStorage` looks clients up through
  `client_id_hash`, a SHA-256 of the `client_id`.
- Tokens keep `family_started_at`, the time the family began. The family lifetime depends on it and it
  must survive rows being pruned.
- `findTokensByFamily` and `findActiveTokensBySubject` return the oldest first.

## Schema reference

All text columns that hold lists (`redirect_uris`, `grant_types`, `scopes`, `metadata`) store JSON.
Column types below are from the MySQL file. SQLite and PostgreSQL use their closest types
(PostgreSQL ids are `CHAR(36)` and times are `TIMESTAMP(0)`).

### `oauth_clients`

| Column | Type | Meaning |
| --- | --- | --- |
| `id` | `CHAR(36)` primary key | Internal UUID. Foreign keys point here |
| `client_id` | `TEXT` | The public `client_id`. A URL for metadata document clients |
| `client_id_hash` | `CHAR(64)` unique | SHA-256 of `client_id`, used for lookups |
| `type` | `VARCHAR(20)` | `registered`, `dynamic` or `metadata_document` |
| `application_type` | `VARCHAR(10)` | `web` or `native` |
| `name` | `VARCHAR(255)` | Display name |
| `client_uri` | `TEXT` null | Home page |
| `logo_uri` | `TEXT` null | Logo (the built-in pages do not show it) |
| `redirect_uris` | `TEXT` | JSON list |
| `grant_types` | `TEXT` | JSON list |
| `scopes` | `TEXT` null | JSON list of allowed scopes. `NULL` means any |
| `token_endpoint_auth_method` | `VARCHAR(30)` | `none`, `client_secret_basic` or `client_secret_post` |
| `secret_hash` | `CHAR(64)` null | SHA-256 of the client secret |
| `allow_introspection` | `TINYINT(1)` | May call `/introspect` |
| `metadata` | `TEXT` null | The registration request or metadata document |
| `metadata_fetched_at` | `DATETIME` null | When the document was fetched |
| `metadata_expires_at` | `DATETIME` null | When to fetch it again |
| `last_used_at` | `DATETIME` null | Last token request or token use |
| `revoked_at` | `DATETIME` null | When the client was revoked |
| `created`, `modified` | `DATETIME` | Row times |

### `oauth_authorization_codes`

| Column | Type | Meaning |
| --- | --- | --- |
| `id` | `CHAR(36)` primary key | Internal UUID |
| `code_hash` | `CHAR(64)` unique | SHA-256 of the code |
| `oauth_client_id` | `CHAR(36)` | Client `id`. Foreign key, `ON DELETE CASCADE` |
| `subject` | `VARCHAR(255)` | The person |
| `redirect_uri` | `TEXT` | The URI the code was sent to |
| `resource` | `TEXT` | Canonical resource |
| `scopes` | `TEXT` | JSON list. Contains `offline_access` when it was requested |
| `code_challenge` | `VARCHAR(128)` | PKCE S256 challenge |
| `family_id` | `CHAR(36)` null | The family issued from the code, set when it is used |
| `expires_at` | `DATETIME` | Expiry |
| `used_at` | `DATETIME` null | When it was exchanged |
| `created` | `DATETIME` | Row time |

### `oauth_tokens`

| Column | Type | Meaning |
| --- | --- | --- |
| `id` | `CHAR(36)` primary key | Internal UUID |
| `token_hash` | `CHAR(64)` unique | SHA-256 of the token |
| `type` | `VARCHAR(10)` | `access`, `refresh` or `personal` |
| `family_id` | `CHAR(36)` | Tokens of one authorization share it |
| `parent_id` | `CHAR(36)` null | The refresh token whose rotation issued this token |
| `oauth_client_id` | `CHAR(36)` null | Client `id`. `NULL` for personal tokens. Foreign key, `ON DELETE CASCADE` |
| `subject` | `VARCHAR(255)` | The person, or the `client_id` for client credentials |
| `subject_type` | `VARCHAR(10)` | `user` or `client` |
| `resource` | `TEXT` | Canonical resource |
| `scopes` | `TEXT` | JSON list of granted scopes |
| `name` | `VARCHAR(255)` null | Name of a personal token |
| `expires_at` | `DATETIME` null | Expiry |
| `used_at` | `DATETIME` null | When a refresh token was rotated |
| `revoked_at` | `DATETIME` null | Revocation |
| `last_used_at` | `DATETIME` null | Last use at a resource (updated at most once a minute) |
| `family_started_at` | `DATETIME` null | When the family began |
| `created`, `modified` | `DATETIME` | Row times |

### `oauth_consents`

| Column | Type | Meaning |
| --- | --- | --- |
| `id` | `CHAR(36)` primary key | Internal UUID |
| `subject` | `VARCHAR(255)` | The person |
| `oauth_client_id` | `CHAR(36)` | Client `id`. Foreign key, `ON DELETE CASCADE` |
| `resource` | `TEXT` | Canonical resource |
| `resource_hash` | `CHAR(64)` | SHA-256 of `resource`, part of the unique key |
| `scopes` | `TEXT` | JSON list of accepted scopes |
| `created`, `modified` | `DATETIME` | Row times |

The pair `(subject, oauth_client_id, resource_hash)` is unique.
