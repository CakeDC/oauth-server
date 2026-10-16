<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Storage\Pdo;

use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Storage\Pdo\PdoStorage;
use CakeDC\OAuth\Server\Support\Time;
use CakeDC\OAuth\Server\Support\Uuid;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Token\Token;
use CakeDC\OAuth\Server\Token\TokenType;
use DateTimeImmutable;
use DateTimeZone;
use PDO;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * A real race between two processes: a request is inserting a token for a client (its transaction is
 * still open, so the row is not visible yet but its foreign key check holds a lock on the client) while
 * prune() picks that client as unused. prune() must wait for the insert and keep the client; it must not
 * delete the client and let the database cascade the new token away once the insert commits.
 *
 * On PostgreSQL the claim UPDATE alone does not wait (it changes no key column, and the insert holds only
 * a key-share lock), so this pins the `SELECT ... FOR UPDATE` that prune() takes first. Runs when
 * OAUTH_TEST_PGSQL_DSN or OAUTH_TEST_MYSQL_DSN is set and proc_open() is available.
 */
class PruneLockTest extends TestCase
{
    /**
     * @return array<string, array{string}>
     */
    public static function engines(): array
    {
        return ['PostgreSQL' => ['PGSQL'], 'MySQL or MariaDB' => ['MYSQL']];
    }

    #[DataProvider('engines')]
    public function testPruneWaitsForATokenInsertInFlightAndKeepsTheClient(string $engine): void
    {
        $dsn = getenv('OAUTH_TEST_' . $engine . '_DSN');
        if (!is_string($dsn) || $dsn === '') {
            $this->markTestSkipped('OAUTH_TEST_' . $engine . '_DSN is not set.');
        }
        if (!function_exists('proc_open')) {
            $this->markTestSkipped('proc_open() is disabled.');
        }
        $user = (string)getenv('OAUTH_TEST_' . $engine . '_USER');
        $password = (string)getenv('OAUTH_TEST_' . $engine . '_PASSWORD');
        $connect = fn(): PDO => new PDO($dsn, $user, $password, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $request = $connect();
        PdoStorage::createTables($request);
        foreach (['oauth_consents', 'oauth_tokens', 'oauth_authorization_codes', 'oauth_clients'] as $table) {
            $request->exec('DELETE FROM ' . $table);
        }
        $storage = new PdoStorage($request);
        $now = new DateTimeImmutable('2026-06-01 12:00:00', new DateTimeZone('UTC'));
        // A dynamic client registered two months ago and never used: a pruning candidate.
        $client = Fixtures::client(['createdAt' => Time::plus($now, -60 * 86400)]);
        $storage->saveClient($client);
        $token = new Token(
            id: Uuid::v4(),
            tokenHash: hash('sha256', Uuid::v4()),
            type: TokenType::Access,
            familyId: Uuid::v4(),
            clientInternalId: $client->id,
            subject: '42',
            subjectType: SubjectType::User,
            resource: Fixtures::MCP,
            scopes: ['content:read'],
            createdAt: $now,
            expiresAt: Time::plus($now, 3600),
        );

        // The request: the token is inserted, the transaction not committed yet.
        $request->beginTransaction();
        $storage->saveToken($token);
        $worker = $this->startWorker($dsn, $user, $password, $now);
        $monitor = $connect();
        $this->waitUntilLocked($monitor, $worker['connection'], $worker['process']);
        $request->commit();
        $result = $this->finish($worker);

        $this->assertSame(0, $result['clients'], 'The client was pruned although a token was being saved.');
        $check = new PdoStorage($monitor);
        $this->assertNotNull($check->findClientById($client->id));
        $this->assertNotNull($check->findTokenById($token->id), 'The new token was cascaded away.');
    }

    /**
     * @return array{process: resource, pipes: array<int, resource>, connection: string}
     */
    private function startWorker(string $dsn, string $user, string $password, DateTimeImmutable $now): array
    {
        $script = dirname(__DIR__, 3) . '/Support/prune-worker.php';
        $env = ['OAUTH_PRUNE_DSN' => $dsn, 'OAUTH_PRUNE_USER' => $user, 'OAUTH_PRUNE_PASSWORD' => $password];
        $process = proc_open(
            [PHP_BINARY, $script, $now->format(DATE_ATOM)],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            null,
            $env + getenv(),
        );
        $this->assertIsResource($process);
        $line = $this->readLine($pipes[1], 10.0);
        if ($line === '') {
            proc_terminate($process);
            $this->fail('The worker did not start: ' . stream_get_contents($pipes[2]));
        }

        return ['process' => $process, 'pipes' => $pipes, 'connection' => $line];
    }

    /**
     * Waits until the worker's connection waits on a row lock (what the insert in flight holds).
     *
     * @param resource $process The worker.
     */
    private function waitUntilLocked(PDO $monitor, string $connection, $process): void
    {
        $sql = $monitor->getAttribute(PDO::ATTR_DRIVER_NAME) === 'pgsql'
            ? "SELECT COUNT(*) FROM pg_stat_activity WHERE pid = ? AND wait_event_type = 'Lock'"
            : "SELECT COUNT(*) FROM information_schema.innodb_trx WHERE trx_mysql_thread_id = ? AND trx_state = 'LOCK WAIT'";
        $statement = $monitor->prepare($sql);
        $deadline = microtime(true) + 15.0;
        while (microtime(true) < $deadline) {
            $statement->execute([(int)$connection]);
            if ((int)$statement->fetchColumn() > 0) {
                return;
            }
            if (!proc_get_status($process)['running']) {
                $this->fail('prune() finished without waiting for the token insert in flight.');
            }
            usleep(20000);
        }
        $this->fail('prune() never waited on the client row.');
    }

    /**
     * @param array{process: resource, pipes: array<int, resource>, connection: string} $worker
     * @return array{codes: int, tokens: int, clients: int}
     */
    private function finish(array $worker): array
    {
        $line = $this->readLine($worker['pipes'][1], 15.0);
        $errors = (string)stream_get_contents($worker['pipes'][2]);
        fclose($worker['pipes'][1]);
        fclose($worker['pipes'][2]);
        $exit = proc_close($worker['process']);
        $this->assertSame(0, $exit, 'The worker failed: ' . $errors);
        $result = json_decode($line, true);
        $this->assertIsArray($result, 'Unexpected worker output: ' . $line . $errors);

        /** @var array{codes: int, tokens: int, clients: int} $result */
        return $result;
    }

    /**
     * @param resource $pipe
     */
    private function readLine($pipe, float $timeout): string
    {
        $deadline = microtime(true) + $timeout;
        $line = '';
        stream_set_blocking($pipe, false);
        while (microtime(true) < $deadline) {
            $chunk = fgets($pipe);
            if ($chunk !== false) {
                $line .= $chunk;
                if (str_ends_with($line, "\n")) {
                    return trim($line);
                }
            }
            if (feof($pipe)) {
                break;
            }
            usleep(10000);
        }

        return trim($line);
    }
}
