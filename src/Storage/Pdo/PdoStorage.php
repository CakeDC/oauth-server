<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Storage\Pdo;

use CakeDC\OAuth\Server\Client\ApplicationType;
use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Client\ClientAuthMethod;
use CakeDC\OAuth\Server\Client\ClientType;
use CakeDC\OAuth\Server\Grant\AuthorizationCode;
use CakeDC\OAuth\Server\Grant\Consent;
use CakeDC\OAuth\Server\Maintenance\PruneResult;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Storage\StorageInterface;
use CakeDC\OAuth\Server\Support\Time;
use CakeDC\OAuth\Server\Token\Token;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use CakeDC\OAuth\Server\Token\TokenType;
use DateTimeImmutable;
use InvalidArgumentException;
use PDO;
use RuntimeException;
use Throwable;

/**
 * Storage on PDO: SQLite, MySQL/MariaDB and PostgreSQL. Create the tables with createTables() or
 * the files in `schema/`.
 */
final class PdoStorage implements StorageInterface
{
    private string $clients;

    private string $codes;

    private string $tokens;

    private string $consents;

    /**
     * @param \PDO $pdo The connection; switched to exception error mode.
     * @param string $tablePrefix Prefix of the four table names.
     * @throws \InvalidArgumentException
     */
    public function __construct(private readonly PDO $pdo, string $tablePrefix = 'oauth_')
    {
        if (preg_match('/^[a-z0-9_]*\z/', $tablePrefix) !== 1) {
            throw new InvalidArgumentException('The table prefix may contain lowercase letters, digits and "_".');
        }
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->clients = $tablePrefix . 'clients';
        $this->codes = $tablePrefix . 'authorization_codes';
        $this->tokens = $tablePrefix . 'tokens';
        $this->consents = $tablePrefix . 'consents';
    }

    /**
     * Creates the tables with the default prefix if they do not exist.
     *
     * @throws \RuntimeException For a driver without a schema file.
     */
    public static function createTables(PDO $pdo): void
    {
        $driver = (string)$pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
        $file = dirname(__DIR__, 3) . '/schema/' . $driver . '.sql';
        $sql = is_file($file) ? file_get_contents($file) : false;
        if ($sql === false) {
            throw new RuntimeException(sprintf('There is no schema for the "%s" driver.', $driver));
        }
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        foreach (preg_split('/;\s*(?:\n|$)/', $sql) ?: [] as $statement) {
            if (trim($statement) !== '') {
                $pdo->exec($statement);
            }
        }
    }

    /**
     * @inheritDoc
     */
    public function findClientByClientId(string $clientId): ?Client
    {
        $rows = $this->select(
            "SELECT * FROM {$this->clients} WHERE client_id_hash = ?",
            [TokenGenerator::hash($clientId)],
        );

        return $rows === [] ? null : $this->client($rows[0]);
    }

    /**
     * @inheritDoc
     */
    public function findClientById(string $id): ?Client
    {
        $rows = $this->select("SELECT * FROM {$this->clients} WHERE id = ?", [$id]);

        return $rows === [] ? null : $this->client($rows[0]);
    }

    /**
     * @inheritDoc
     */
    public function saveClient(Client $client): void
    {
        $row = [
            'client_id' => $client->clientId,
            'client_id_hash' => TokenGenerator::hash($client->clientId),
            'type' => $client->type->value,
            'application_type' => $client->applicationType->value,
            'name' => $client->name,
            'client_uri' => $client->clientUri,
            'logo_uri' => $client->logoUri,
            'redirect_uris' => self::json($client->redirectUris),
            'grant_types' => self::json($client->grantTypes),
            'scopes' => $client->scopes === null ? null : self::json($client->scopes),
            'token_endpoint_auth_method' => $client->authMethod->value,
            'secret_hash' => $client->secretHash,
            'allow_introspection' => $client->allowIntrospection,
            'metadata' => $client->metadata === null ? null : self::json($client->metadata),
            'metadata_fetched_at' => self::time($client->metadataFetchedAt),
            'metadata_expires_at' => self::time($client->metadataExpiresAt),
            'last_used_at' => self::time($client->lastUsedAt),
            'revoked_at' => self::time($client->revokedAt),
            'modified' => gmdate(Time::FORMAT),
        ];
        if ($this->select("SELECT id FROM {$this->clients} WHERE id = ?", [$client->id]) !== []) {
            $this->update($this->clients, $client->id, $row);

            return;
        }
        $this->insert($this->clients, ['id' => $client->id, 'created' => Time::format($client->createdAt)] + $row);
    }

    /**
     * @inheritDoc
     */
    public function touchClient(string $id, DateTimeImmutable $at): void
    {
        $this->execute("UPDATE {$this->clients} SET last_used_at = ? WHERE id = ?", [Time::format($at), $id]);
    }

    /**
     * @inheritDoc
     */
    public function findClients(?ClientType $type = null): array
    {
        $rows = $type === null
            ? $this->select("SELECT * FROM {$this->clients} ORDER BY created, id", [])
            : $this->select("SELECT * FROM {$this->clients} WHERE type = ? ORDER BY created, id", [$type->value]);

        return array_map($this->client(...), $rows);
    }

    /**
     * @inheritDoc
     */
    public function saveCode(AuthorizationCode $code): void
    {
        $this->insert($this->codes, [
            'id' => $code->id,
            'code_hash' => $code->codeHash,
            'oauth_client_id' => $code->clientInternalId,
            'subject' => $code->subject,
            'redirect_uri' => $code->redirectUri,
            'resource' => $code->resource,
            'scopes' => self::json($code->scopes),
            'code_challenge' => $code->codeChallenge,
            'family_id' => $code->familyId,
            'expires_at' => Time::format($code->expiresAt),
            'used_at' => self::time($code->usedAt),
            'created' => Time::format($code->createdAt),
        ]);
    }

    /**
     * @inheritDoc
     */
    public function findCodeByHash(string $hash): ?AuthorizationCode
    {
        $rows = $this->select("SELECT * FROM {$this->codes} WHERE code_hash = ?", [$hash]);
        if ($rows === []) {
            return null;
        }
        $row = $rows[0];

        return new AuthorizationCode(
            id: (string)$row['id'],
            codeHash: (string)$row['code_hash'],
            clientInternalId: (string)$row['oauth_client_id'],
            subject: (string)$row['subject'],
            redirectUri: (string)$row['redirect_uri'],
            resource: (string)$row['resource'],
            scopes: self::stringList($row['scopes']),
            codeChallenge: (string)$row['code_challenge'],
            expiresAt: Time::parse((string)$row['expires_at']),
            createdAt: Time::parse((string)$row['created']),
            usedAt: self::date($row['used_at']),
            familyId: $row['family_id'] === null ? null : (string)$row['family_id'],
        );
    }

    /**
     * @inheritDoc
     */
    public function consumeCode(string $id, DateTimeImmutable $at, string $familyId): bool
    {
        return $this->execute(
            "UPDATE {$this->codes} SET used_at = ?, family_id = ? WHERE id = ? AND used_at IS NULL",
            [Time::format($at), $familyId, $id],
        ) === 1;
    }

    /**
     * @inheritDoc
     */
    public function saveToken(Token $token): void
    {
        $this->insert($this->tokens, [
            'id' => $token->id,
            'token_hash' => $token->tokenHash,
            'type' => $token->type->value,
            'family_id' => $token->familyId,
            'parent_id' => $token->parentId,
            'oauth_client_id' => $token->clientInternalId,
            'subject' => $token->subject,
            'subject_type' => $token->subjectType->value,
            'resource' => $token->resource,
            'scopes' => self::json($token->scopes),
            'name' => $token->name,
            'expires_at' => self::time($token->expiresAt),
            'used_at' => self::time($token->usedAt),
            'revoked_at' => self::time($token->revokedAt),
            'last_used_at' => self::time($token->lastUsedAt),
            'created' => Time::format($token->createdAt),
            'modified' => Time::format($token->createdAt),
        ]);
    }

    /**
     * @inheritDoc
     */
    public function findTokenByHash(string $hash): ?Token
    {
        $rows = $this->select("SELECT * FROM {$this->tokens} WHERE token_hash = ?", [$hash]);

        return $rows === [] ? null : $this->token($rows[0]);
    }

    /**
     * @inheritDoc
     */
    public function findTokenById(string $id): ?Token
    {
        $rows = $this->select("SELECT * FROM {$this->tokens} WHERE id = ?", [$id]);

        return $rows === [] ? null : $this->token($rows[0]);
    }

    /**
     * @inheritDoc
     */
    public function markTokenUsed(string $id, DateTimeImmutable $at): bool
    {
        return $this->execute(
            "UPDATE {$this->tokens} SET used_at = ?, modified = ? WHERE id = ? AND used_at IS NULL",
            [Time::format($at), Time::format($at), $id],
        ) === 1;
    }

    /**
     * @inheritDoc
     */
    public function revokeToken(string $id, DateTimeImmutable $at): void
    {
        $this->revokeWhere('id = ?', [$id], $at);
    }

    /**
     * @inheritDoc
     */
    public function revokeTokenFamily(string $familyId, DateTimeImmutable $at): int
    {
        return $this->revokeWhere('family_id = ?', [$familyId], $at);
    }

    /**
     * @inheritDoc
     */
    public function revokeTokensBySubject(string $subject, SubjectType $type, DateTimeImmutable $at): int
    {
        return $this->revokeWhere('subject = ? AND subject_type = ?', [$subject, $type->value], $at);
    }

    /**
     * @inheritDoc
     */
    public function revokeTokensByClient(string $clientInternalId, DateTimeImmutable $at): int
    {
        return $this->revokeWhere('oauth_client_id = ?', [$clientInternalId], $at);
    }

    /**
     * @inheritDoc
     */
    public function findTokensByFamily(string $familyId): array
    {
        $rows = $this->select("SELECT * FROM {$this->tokens} WHERE family_id = ? ORDER BY created, id", [$familyId]);

        return array_map($this->token(...), $rows);
    }

    /**
     * @inheritDoc
     */
    public function findActiveTokensBySubject(string $subject, SubjectType $type, DateTimeImmutable $now): array
    {
        $rows = $this->select(
            "SELECT * FROM {$this->tokens} WHERE subject = ? AND subject_type = ? AND revoked_at IS NULL"
            . ' AND (expires_at IS NULL OR expires_at > ?) ORDER BY created, id',
            [$subject, $type->value, Time::format($now)],
        );

        return array_map($this->token(...), $rows);
    }

    /**
     * @inheritDoc
     */
    public function touchToken(string $id, DateTimeImmutable $at): void
    {
        $this->execute("UPDATE {$this->tokens} SET last_used_at = ? WHERE id = ?", [Time::format($at), $id]);
    }

    /**
     * @inheritDoc
     */
    public function findConsent(string $subject, string $clientInternalId, string $resource): ?Consent
    {
        $rows = $this->select(
            "SELECT * FROM {$this->consents} WHERE subject = ? AND oauth_client_id = ? AND resource_hash = ?",
            [$subject, $clientInternalId, hash('sha256', $resource)],
        );
        if ($rows === []) {
            return null;
        }
        $row = $rows[0];

        return new Consent(
            (string)$row['id'],
            (string)$row['subject'],
            (string)$row['oauth_client_id'],
            (string)$row['resource'],
            self::stringList($row['scopes']),
            Time::parse((string)$row['created']),
            Time::parse((string)$row['modified']),
        );
    }

    /**
     * @inheritDoc
     */
    public function saveConsent(Consent $consent): void
    {
        $existing = $this->findConsent($consent->subject, $consent->clientInternalId, $consent->resource);
        if ($existing !== null) {
            $this->update($this->consents, $existing->id, [
                'scopes' => self::json($consent->scopes),
                'modified' => Time::format($consent->modifiedAt),
            ]);

            return;
        }
        $this->insert($this->consents, [
            'id' => $consent->id,
            'subject' => $consent->subject,
            'oauth_client_id' => $consent->clientInternalId,
            'resource' => $consent->resource,
            'resource_hash' => hash('sha256', $consent->resource),
            'scopes' => self::json($consent->scopes),
            'created' => Time::format($consent->createdAt),
            'modified' => Time::format($consent->modifiedAt),
        ]);
    }

    /**
     * @inheritDoc
     */
    public function deleteConsent(string $subject, string $clientInternalId, string $resource): void
    {
        $this->execute(
            "DELETE FROM {$this->consents} WHERE subject = ? AND oauth_client_id = ? AND resource_hash = ?",
            [$subject, $clientInternalId, hash('sha256', $resource)],
        );
    }

    /**
     * @inheritDoc
     */
    public function prune(DateTimeImmutable $now, int $retentionSeconds, int $unusedClientSeconds): PruneResult
    {
        $nowText = Time::format($now);
        $cutoff = Time::format(Time::plus($now, -$retentionSeconds));
        $codes = $this->execute("DELETE FROM {$this->codes} WHERE expires_at < ?", [$nowText]);
        $tokens = $this->execute(
            "DELETE FROM {$this->tokens} WHERE (revoked_at IS NOT NULL AND revoked_at < ?)"
            . ' OR (expires_at IS NOT NULL AND expires_at < ?)',
            [$cutoff, $cutoff],
        );
        $candidates = $this->select(
            "SELECT c.id FROM {$this->clients} c WHERE c.type IN (?, ?) AND c.created < ?"
            . ' AND (c.last_used_at IS NULL OR c.last_used_at < ?)'
            . " AND NOT EXISTS (SELECT 1 FROM {$this->tokens} t WHERE t.oauth_client_id = c.id"
            . ' AND t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at > ?))',
            [
                ClientType::Dynamic->value,
                ClientType::MetadataDocument->value,
                Time::format(Time::plus($now, -$unusedClientSeconds)),
                $cutoff,
                $nowText,
            ],
        );
        $clients = 0;
        foreach ($candidates as $candidate) {
            $id = (string)$candidate['id'];
            $this->pdo->beginTransaction();
            try {
                $tokens += $this->execute("DELETE FROM {$this->tokens} WHERE oauth_client_id = ?", [$id]);
                $codes += $this->execute("DELETE FROM {$this->codes} WHERE oauth_client_id = ?", [$id]);
                $this->execute("DELETE FROM {$this->consents} WHERE oauth_client_id = ?", [$id]);
                $clients += $this->execute("DELETE FROM {$this->clients} WHERE id = ?", [$id]);
                $this->pdo->commit();
            } catch (Throwable $e) {
                $this->pdo->rollBack();
                throw $e;
            }
        }

        return new PruneResult($codes, $tokens, $clients);
    }

    /**
     * Revokes the live tokens matching $where.
     *
     * @param string $where SQL condition with `?` placeholders.
     * @param list<string> $params Its values.
     */
    private function revokeWhere(string $where, array $params, DateTimeImmutable $at): int
    {
        $time = Time::format($at);

        return $this->execute(
            "UPDATE {$this->tokens} SET revoked_at = ?, modified = ? WHERE revoked_at IS NULL AND {$where}",
            [$time, $time, ...$params],
        );
    }

    /**
     * Inserts a row.
     *
     * @param array<string, mixed> $row Column => value.
     */
    private function insert(string $table, array $row): void
    {
        $this->execute(
            sprintf(
                'INSERT INTO %s (%s) VALUES (%s)',
                $table,
                implode(', ', array_keys($row)),
                implode(', ', array_fill(0, count($row), '?')),
            ),
            array_values($row),
        );
    }

    /**
     * Updates the row with this id.
     *
     * @param array<string, mixed> $row Column => value.
     */
    private function update(string $table, string $id, array $row): void
    {
        $sets = implode(', ', array_map(fn(string $column): string => $column . ' = ?', array_keys($row)));
        $this->execute("UPDATE {$table} SET {$sets} WHERE id = ?", [...array_values($row), $id]);
    }

    /**
     * Runs a statement; returns the affected rows.
     *
     * @param list<mixed> $params Positional values.
     */
    private function execute(string $sql, array $params): int
    {
        $statement = $this->pdo->prepare($sql);
        foreach ($params as $index => $value) {
            $statement->bindValue($index + 1, $value, match (true) {
                $value === null => PDO::PARAM_NULL,
                is_bool($value) => PDO::PARAM_BOOL,
                is_int($value) => PDO::PARAM_INT,
                default => PDO::PARAM_STR,
            });
        }
        $statement->execute();

        return $statement->rowCount();
    }

    /**
     * Runs a query.
     *
     * @param list<mixed> $params Positional values.
     * @return list<array<string, mixed>>
     */
    private function select(string $sql, array $params): array
    {
        $statement = $this->pdo->prepare($sql);
        foreach ($params as $index => $value) {
            $statement->bindValue($index + 1, $value, $value === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
        }
        $statement->execute();

        /** @var list<array<string, mixed>> $rows */
        $rows = $statement->fetchAll(PDO::FETCH_ASSOC);

        return $rows;
    }

    /**
     * Builds a client from a row.
     *
     * @param array<string, mixed> $row Row.
     */
    private function client(array $row): Client
    {
        return new Client(
            id: (string)$row['id'],
            clientId: (string)$row['client_id'],
            type: ClientType::from((string)$row['type']),
            applicationType: ApplicationType::from((string)$row['application_type']),
            name: (string)$row['name'],
            redirectUris: self::stringList($row['redirect_uris']),
            grantTypes: self::stringList($row['grant_types']),
            authMethod: ClientAuthMethod::from((string)$row['token_endpoint_auth_method']),
            createdAt: Time::parse((string)$row['created']),
            secretHash: $row['secret_hash'] === null ? null : (string)$row['secret_hash'],
            scopes: $row['scopes'] === null ? null : self::stringList($row['scopes']),
            clientUri: $row['client_uri'] === null ? null : (string)$row['client_uri'],
            logoUri: $row['logo_uri'] === null ? null : (string)$row['logo_uri'],
            allowIntrospection: (bool)$row['allow_introspection'],
            metadata: $row['metadata'] === null ? null : self::map($row['metadata']),
            metadataFetchedAt: self::date($row['metadata_fetched_at']),
            metadataExpiresAt: self::date($row['metadata_expires_at']),
            lastUsedAt: self::date($row['last_used_at']),
            revokedAt: self::date($row['revoked_at']),
        );
    }

    /**
     * Builds a token from a row.
     *
     * @param array<string, mixed> $row Row.
     */
    private function token(array $row): Token
    {
        return new Token(
            id: (string)$row['id'],
            tokenHash: (string)$row['token_hash'],
            type: TokenType::from((string)$row['type']),
            familyId: (string)$row['family_id'],
            clientInternalId: $row['oauth_client_id'] === null ? null : (string)$row['oauth_client_id'],
            subject: (string)$row['subject'],
            subjectType: SubjectType::from((string)$row['subject_type']),
            resource: (string)$row['resource'],
            scopes: self::stringList($row['scopes']),
            createdAt: Time::parse((string)$row['created']),
            expiresAt: self::date($row['expires_at']),
            name: $row['name'] === null ? null : (string)$row['name'],
            parentId: $row['parent_id'] === null ? null : (string)$row['parent_id'],
            usedAt: self::date($row['used_at']),
            revokedAt: self::date($row['revoked_at']),
            lastUsedAt: self::date($row['last_used_at']),
        );
    }

    /**
     * A stored time, or null.
     */
    private static function time(?DateTimeImmutable $time): ?string
    {
        return $time === null ? null : Time::format($time);
    }

    /**
     * A stored time column read back.
     */
    private static function date(mixed $value): ?DateTimeImmutable
    {
        return $value === null ? null : Time::parse((string)$value);
    }

    /**
     * JSON for a column.
     *
     * @param array<mixed> $value Value.
     */
    private static function json(array $value): string
    {
        return json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    /**
     * A JSON list of strings read back.
     *
     * @return list<string>
     */
    private static function stringList(mixed $value): array
    {
        $decoded = json_decode((string)$value, true);

        return is_array($decoded) ? array_values(array_map('strval', $decoded)) : [];
    }

    /**
     * A JSON object read back.
     *
     * @return array<string, mixed>
     */
    private static function map(mixed $value): array
    {
        $decoded = json_decode((string)$value, true);
        if (!is_array($decoded)) {
            return [];
        }
        $map = [];
        foreach ($decoded as $key => $item) {
            $map[(string)$key] = $item;
        }

        return $map;
    }
}
