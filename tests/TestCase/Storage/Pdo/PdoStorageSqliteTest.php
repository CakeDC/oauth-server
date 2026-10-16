<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Storage\Pdo;

use CakeDC\OAuth\Server\Storage\Pdo\PdoStorage;
use CakeDC\OAuth\Server\Storage\StorageInterface;
use CakeDC\OAuth\Server\Test\Support\HookedPdo;
use CakeDC\OAuth\Server\Testing\StorageContractTestCase;
use InvalidArgumentException;
use PDO;

class PdoStorageSqliteTest extends StorageContractTestCase
{
    use PdoConcurrencyTestsTrait;

    protected function connect(): HookedPdo
    {
        $pdo = new HookedPdo('sqlite::memory:');
        PdoStorage::createTables($pdo);
        PdoStorage::createTables($pdo);

        return $pdo;
    }

    protected function createStorage(): StorageInterface
    {
        return new PdoStorage($this->connect());
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
