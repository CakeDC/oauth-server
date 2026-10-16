<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Storage\Pdo;

use CakeDC\OAuth\Server\Storage\Pdo\PdoStorage;
use CakeDC\OAuth\Server\Storage\StorageInterface;
use CakeDC\OAuth\Server\Testing\StorageContractTestCase;
use InvalidArgumentException;
use PDO;

class PdoStorageSqliteTest extends StorageContractTestCase
{
    protected function createStorage(): StorageInterface
    {
        $pdo = new PDO('sqlite::memory:');
        PdoStorage::createTables($pdo);
        PdoStorage::createTables($pdo);

        return new PdoStorage($pdo);
    }

    public function testRejectsAnUnsafeTablePrefix(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new PdoStorage(new PDO('sqlite::memory:'), 'x; DROP TABLE');
    }

    public function testRejectsATablePrefixWithATrailingNewline(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new PdoStorage(new PDO('sqlite::memory:'), "oauth_\n");
    }
}
