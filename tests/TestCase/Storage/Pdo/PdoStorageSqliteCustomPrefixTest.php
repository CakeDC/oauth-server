<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Storage\Pdo;

use CakeDC\OAuth\Server\Storage\Pdo\PdoStorage;
use CakeDC\OAuth\Server\Storage\StorageInterface;
use CakeDC\OAuth\Server\Testing\StorageContractTestCase;
use InvalidArgumentException;
use PDO;

class PdoStorageSqliteCustomPrefixTest extends StorageContractTestCase
{
    protected function createStorage(): StorageInterface
    {
        $pdo = new PDO('sqlite::memory:');
        PdoStorage::createTables($pdo, 'custom_');
        PdoStorage::createTables($pdo, 'custom_');

        return new PdoStorage($pdo, 'custom_');
    }

    public function testOnlyThePrefixedTablesAreCreated(): void
    {
        $pdo = new PDO('sqlite::memory:');
        PdoStorage::createTables($pdo, 'custom_');

        $tables = $pdo->query("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            ?->fetchAll(PDO::FETCH_COLUMN);
        $this->assertSame(
            ['custom_authorization_codes', 'custom_clients', 'custom_consents', 'custom_tokens'],
            $tables,
        );
        $columns = $pdo->query('PRAGMA table_info(custom_tokens)')?->fetchAll(PDO::FETCH_COLUMN, 1);
        $this->assertContains('oauth_client_id', $columns);
    }

    public function testCreateTablesRejectsAnUnsafePrefix(): void
    {
        $this->expectException(InvalidArgumentException::class);

        PdoStorage::createTables(new PDO('sqlite::memory:'), "custom_\n");
    }
}
