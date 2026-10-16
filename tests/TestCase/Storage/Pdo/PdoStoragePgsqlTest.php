<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Storage\Pdo;

use CakeDC\OAuth\Server\Storage\Pdo\PdoStorage;
use CakeDC\OAuth\Server\Storage\StorageInterface;
use CakeDC\OAuth\Server\Test\Support\HookedPdo;
use CakeDC\OAuth\Server\Testing\StorageContractTestCase;

/**
 * Runs when OAUTH_TEST_PGSQL_DSN is set, for example "pgsql:host=127.0.0.1;port=5432;dbname=oauth".
 */
class PdoStoragePgsqlTest extends StorageContractTestCase
{
    use PdoConcurrencyTestsTrait;

    protected function connect(): HookedPdo
    {
        $dsn = getenv('OAUTH_TEST_PGSQL_DSN');
        if (!is_string($dsn) || $dsn === '') {
            $this->markTestSkipped('OAUTH_TEST_PGSQL_DSN is not set.');
        }
        $pdo = new HookedPdo($dsn, (string)getenv('OAUTH_TEST_PGSQL_USER'), (string)getenv('OAUTH_TEST_PGSQL_PASSWORD'));
        PdoStorage::createTables($pdo);
        foreach (['oauth_consents', 'oauth_tokens', 'oauth_authorization_codes', 'oauth_clients'] as $table) {
            $pdo->exec('DELETE FROM ' . $table);
        }

        return $pdo;
    }

    protected function createStorage(): StorageInterface
    {
        return new PdoStorage($this->connect());
    }
}
