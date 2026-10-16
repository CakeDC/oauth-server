<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Support;

use DateInterval;
use Psr\SimpleCache\CacheInterface;
use RuntimeException;

/**
 * A PSR-16 cache whose server is down: every read and write throws (as a Redis client does when the
 * connection is lost).
 */
final class BrokenCache implements CacheInterface
{
    public int $calls = 0;

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->fail();
    }

    public function set(string $key, mixed $value, null|int|DateInterval $ttl = null): bool
    {
        return $this->fail();
    }

    public function delete(string $key): bool
    {
        return $this->fail();
    }

    public function clear(): bool
    {
        return $this->fail();
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        return $this->fail();
    }

    public function setMultiple(iterable $values, null|int|DateInterval $ttl = null): bool
    {
        return $this->fail();
    }

    public function deleteMultiple(iterable $keys): bool
    {
        return $this->fail();
    }

    public function has(string $key): bool
    {
        return $this->fail();
    }

    private function fail(): never
    {
        $this->calls++;

        throw new RuntimeException('Connection refused [tcp://cache.internal:6379]');
    }
}
