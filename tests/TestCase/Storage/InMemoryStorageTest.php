<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Storage;

use CakeDC\OAuth\Server\Storage\InMemory\InMemoryStorage;
use CakeDC\OAuth\Server\Storage\StorageInterface;
use CakeDC\OAuth\Server\Testing\StorageContractTestCase;

class InMemoryStorageTest extends StorageContractTestCase
{
    protected function createStorage(): StorageInterface
    {
        return new InMemoryStorage();
    }
}
