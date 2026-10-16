<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Support;

use DateTimeImmutable;
use DateTimeZone;

/**
 * UTC time helpers. Storage keeps times as `Y-m-d H:i:s` in UTC.
 */
final class Time
{
    public const FORMAT = 'Y-m-d H:i:s';

    /**
     * $time moved by $seconds (negative goes back).
     */
    public static function plus(DateTimeImmutable $time, int $seconds): DateTimeImmutable
    {
        return $time->setTimestamp($time->getTimestamp() + $seconds);
    }

    /**
     * $time in UTC as `Y-m-d H:i:s`.
     */
    public static function format(DateTimeImmutable $time): string
    {
        return $time->setTimezone(new DateTimeZone('UTC'))->format(self::FORMAT);
    }

    /**
     * Reads a stored UTC time.
     */
    public static function parse(string $value): DateTimeImmutable
    {
        return new DateTimeImmutable($value, new DateTimeZone('UTC'));
    }
}
