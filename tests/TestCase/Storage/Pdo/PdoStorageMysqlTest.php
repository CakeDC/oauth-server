<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Storage\Pdo;

use CakeDC\OAuth\Server\Storage\Pdo\PdoStorage;
use CakeDC\OAuth\Server\Storage\StorageInterface;
use CakeDC\OAuth\Server\Testing\StorageContractTestCase;
use PDO;

/**
 * Runs when OAUTH_TEST_MYSQL_DSN is set, for example "mysql:host=127.0.0.1;port=3306;dbname=oauth".
 */
class PdoStorageMysqlTest extends StorageContractTestCase
{
    protected function createStorage(): StorageInterface
    {
        $dsn = getenv('OAUTH_TEST_MYSQL_DSN');
        if (!is_string($dsn) || $dsn === '') {
            $this->markTestSkipped('OAUTH_TEST_MYSQL_DSN is not set.');
        }
        $pdo = new PDO($dsn, (string)getenv('OAUTH_TEST_MYSQL_USER'), (string)getenv('OAUTH_TEST_MYSQL_PASSWORD'));
        PdoStorage::createTables($pdo);
        foreach (['oauth_consents', 'oauth_tokens', 'oauth_authorization_codes', 'oauth_clients'] as $table) {
            $pdo->exec('DELETE FROM ' . $table);
        }

        return new PdoStorage($pdo);
    }
}
