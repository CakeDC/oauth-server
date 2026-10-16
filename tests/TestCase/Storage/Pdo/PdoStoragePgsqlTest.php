<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Storage\Pdo;

use CakeDC\OAuth\Server\Storage\Pdo\PdoStorage;
use CakeDC\OAuth\Server\Storage\StorageInterface;
use CakeDC\OAuth\Server\Testing\StorageContractTestCase;
use PDO;

/**
 * Runs when OAUTH_TEST_PGSQL_DSN is set, for example "pgsql:host=127.0.0.1;port=5432;dbname=oauth".
 */
class PdoStoragePgsqlTest extends StorageContractTestCase
{
    protected function createStorage(): StorageInterface
    {
        $dsn = getenv('OAUTH_TEST_PGSQL_DSN');
        if (!is_string($dsn) || $dsn === '') {
            $this->markTestSkipped('OAUTH_TEST_PGSQL_DSN is not set.');
        }
        $pdo = new PDO($dsn, (string)getenv('OAUTH_TEST_PGSQL_USER'), (string)getenv('OAUTH_TEST_PGSQL_PASSWORD'));
        PdoStorage::createTables($pdo);
        foreach (['oauth_consents', 'oauth_tokens', 'oauth_authorization_codes', 'oauth_clients'] as $table) {
            $pdo->exec('DELETE FROM ' . $table);
        }

        return new PdoStorage($pdo);
    }
}
