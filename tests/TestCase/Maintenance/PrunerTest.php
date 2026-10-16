<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Maintenance;

use CakeDC\OAuth\Server\Maintenance\Pruner;
use CakeDC\OAuth\Server\Maintenance\PruneResult;
use CakeDC\OAuth\Server\Storage\MaintenanceInterface;
use CakeDC\OAuth\Server\Testing\FrozenClock;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

class PrunerTest extends TestCase
{
    public function testPassesTheRetentionToTheStorage(): void
    {
        $storage = new class implements MaintenanceInterface {
            public array $calls = [];

            public function prune(DateTimeImmutable $now, int $retentionSeconds, int $unusedClientSeconds): PruneResult
            {
                $this->calls[] = [$now, $retentionSeconds, $unusedClientSeconds];

                return new PruneResult(1, 2, 3);
            }
        };
        $clock = new FrozenClock();

        $result = (new Pruner($storage, $clock, 3, 7200))->prune();

        $this->assertSame(3, $result->clients);
        $this->assertEquals([[$clock->now(), 3 * 86400, 7200]], $storage->calls);
    }
}
