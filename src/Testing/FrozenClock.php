<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Testing;

use CakeDC\OAuth\Server\Support\Time;
use DateTimeImmutable;
use DateTimeZone;
use Psr\Clock\ClockInterface;

/**
 * A clock for tests that only moves when told to.
 */
final class FrozenClock implements ClockInterface
{
    private DateTimeImmutable $now;

    /**
     * Starts at $now, or at 2026-01-01 00:00:00 UTC.
     */
    public function __construct(?DateTimeImmutable $now = null)
    {
        $utc = new DateTimeZone('UTC');
        $this->now = ($now ?? new DateTimeImmutable('2026-01-01 00:00:00', $utc))->setTimezone($utc);
    }

    /**
     * @inheritDoc
     */
    public function now(): DateTimeImmutable
    {
        return $this->now;
    }

    /**
     * Moves the clock forward by $seconds.
     */
    public function advance(int $seconds): void
    {
        $this->now = Time::plus($this->now, $seconds);
    }
}
