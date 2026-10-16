<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Clock;

use CakeDC\OAuth\Server\Clock\SystemClock;
use CakeDC\OAuth\Server\Testing\FrozenClock;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

class ClockTest extends TestCase
{
    public function testSystemClockIsUtc(): void
    {
        $now = (new SystemClock())->now();

        $this->assertSame('UTC', $now->getTimezone()->getName());
        $this->assertEqualsWithDelta(time(), $now->getTimestamp(), 2);
    }

    public function testFrozenClockMovesOnlyWhenAdvanced(): void
    {
        $clock = new FrozenClock(new DateTimeImmutable('2026-03-01 10:00:00'));

        $this->assertSame('2026-03-01 10:00:00', $clock->now()->format('Y-m-d H:i:s'));
        $clock->advance(90);
        $this->assertSame('2026-03-01 10:01:30', $clock->now()->format('Y-m-d H:i:s'));
        $this->assertSame('2026-01-01 00:00:00', (new FrozenClock())->now()->format('Y-m-d H:i:s'));
    }
}
