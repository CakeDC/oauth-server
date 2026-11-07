<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Storage\Pdo;

use CakeDC\OAuth\Server\Clock\SystemClock;
use CakeDC\OAuth\Server\Config\Lifetimes;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Storage\Pdo\PdoStorage;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\RecordingEventDispatcher;
use CakeDC\OAuth\Server\Token\Token;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use CakeDC\OAuth\Server\Token\TokenIssuer;
use CakeDC\OAuth\Server\Token\TokenType;
use PDO;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Sixteen processes present the same refresh token at the same moment, as the workers of one client do
 * when its access token expires under load. Every one of them gets the winner's pair and the connection
 * survives. Runs on SQLite always, and on PostgreSQL and MySQL or MariaDB when OAUTH_TEST_PGSQL_DSN or
 * OAUTH_TEST_MYSQL_DSN is set. Needs proc_open().
 */
class ConcurrentRefreshTest extends TestCase
{
    private const WORKERS = 16;

    private ?string $sqliteFile = null;

    protected function tearDown(): void
    {
        if ($this->sqliteFile !== null && is_file($this->sqliteFile)) {
            unlink($this->sqliteFile);
        }
    }

    /**
     * @return array<string, array{string}>
     */
    public static function engines(): array
    {
        return ['SQLite' => ['SQLITE'], 'PostgreSQL' => ['PGSQL'], 'MySQL or MariaDB' => ['MYSQL']];
    }

    #[DataProvider('engines')]
    public function testConcurrentRefreshesAllGetTheWinnersPair(string $engine): void
    {
        if (!function_exists('proc_open')) {
            $this->markTestSkipped('proc_open() is disabled.');
        }
        [$dsn, $user, $password] = $this->connection($engine);
        $pdo = new PDO($dsn, $user, $password, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        PdoStorage::createTables($pdo);
        foreach (['oauth_consents', 'oauth_tokens', 'oauth_authorization_codes', 'oauth_clients'] as $table) {
            $pdo->exec('DELETE FROM ' . $table);
        }
        $storage = new PdoStorage($pdo);
        $client = Fixtures::client();
        $storage->saveClient($client);
        $initial = (new TokenIssuer($storage, new TokenGenerator(), new SystemClock(), new RecordingEventDispatcher(), new Lifetimes()))
            ->issue($client, '42', SubjectType::User, Fixtures::resources()->defaultResource(), ['content:write'], 'family-1', true);

        $start = microtime(true) + 1.5;
        $workers = [];
        for ($i = 0; $i < self::WORKERS; $i++) {
            $workers[] = $this->start($dsn, $user, $password, (string)$initial->refreshToken, $client->id, $start);
        }
        $answers = array_map(fn(array $worker): array => $this->finish($worker), $workers);

        $errors = array_filter(array_column($answers, 'error'));
        $this->assertSame([], $errors, 'Some workers lost the connection.');
        $this->assertCount(1, array_unique(array_column($answers, 'refresh')), 'Every worker got the same pair.');
        $this->assertCount(1, array_unique(array_column($answers, 'access')));
        $live = array_filter(
            $storage->findTokensByFamily('family-1'),
            fn(Token $t): bool => $t->type === TokenType::Refresh && $t->revokedAt === null && $t->usedAt === null,
        );
        $this->assertCount(1, $live, 'One live refresh token, the one every worker holds.');
        $this->assertSame(TokenGenerator::hash((string)$answers[0]['refresh']), array_values($live)[0]->tokenHash);
    }

    /**
     * @return array{string, string, string}
     */
    private function connection(string $engine): array
    {
        if ($engine === 'SQLITE') {
            $this->sqliteFile = (string)tempnam(sys_get_temp_dir(), 'oauth-refresh-');

            return ['sqlite:' . $this->sqliteFile, '', ''];
        }
        $dsn = getenv('OAUTH_TEST_' . $engine . '_DSN');
        if (!is_string($dsn) || $dsn === '') {
            $this->markTestSkipped('OAUTH_TEST_' . $engine . '_DSN is not set.');
        }

        return [$dsn, (string)getenv('OAUTH_TEST_' . $engine . '_USER'), (string)getenv('OAUTH_TEST_' . $engine . '_PASSWORD')];
    }

    /**
     * @return array{process: resource, pipes: array<int, resource>}
     */
    private function start(string $dsn, string $user, string $password, string $token, string $clientId, float $at): array
    {
        $env = ['OAUTH_REFRESH_DSN' => $dsn, 'OAUTH_REFRESH_USER' => $user, 'OAUTH_REFRESH_PASSWORD' => $password];
        $process = proc_open(
            [PHP_BINARY, dirname(__DIR__, 3) . '/Support/refresh-worker.php', $token, $clientId, sprintf('%.6F', $at)],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            null,
            $env + getenv(),
        );
        $this->assertIsResource($process);

        return ['process' => $process, 'pipes' => $pipes];
    }

    /**
     * @param array{process: resource, pipes: array<int, resource>} $worker
     * @return array<string, string|null>
     */
    private function finish(array $worker): array
    {
        $output = (string)stream_get_contents($worker['pipes'][1]);
        $errors = (string)stream_get_contents($worker['pipes'][2]);
        fclose($worker['pipes'][1]);
        fclose($worker['pipes'][2]);
        proc_close($worker['process']);
        $answer = json_decode(trim($output), true);
        $this->assertIsArray($answer, 'Unexpected worker output: ' . $output . $errors);

        /** @var array<string, string|null> $answer */
        return $answer;
    }
}
