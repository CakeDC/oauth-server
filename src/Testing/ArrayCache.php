<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Testing;

use CakeDC\OAuth\Server\Clock\SystemClock;
use DateInterval;
use Psr\Clock\ClockInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * A PSR-16 cache in a PHP array, for tests and single-process examples.
 */
final class ArrayCache implements CacheInterface
{
    /**
     * @var array<string, array{0: mixed, 1: int|null}>
     */
    private array $items = [];

    private ClockInterface $clock;

    /**
     * Uses $clock for expiry, the system clock by default.
     */
    public function __construct(?ClockInterface $clock = null)
    {
        $this->clock = $clock ?? new SystemClock();
    }

    /**
     * @inheritDoc
     */
    public function get(string $key, mixed $default = null): mixed
    {
        $this->checkKey($key);

        return $this->has($key) ? $this->items[$key][0] : $default;
    }

    /**
     * @inheritDoc
     */
    public function set(string $key, mixed $value, null|int|DateInterval $ttl = null): bool
    {
        $this->checkKey($key);
        if ($ttl instanceof DateInterval) {
            $ttl = $this->clock->now()->add($ttl)->getTimestamp() - $this->clock->now()->getTimestamp();
        }
        $this->items[$key] = [$value, $ttl === null ? null : $this->clock->now()->getTimestamp() + $ttl];

        return true;
    }

    /**
     * @inheritDoc
     */
    public function delete(string $key): bool
    {
        $this->checkKey($key);
        unset($this->items[$key]);

        return true;
    }

    /**
     * @inheritDoc
     */
    public function clear(): bool
    {
        $this->items = [];

        return true;
    }

    /**
     * @inheritDoc
     */
    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $values = [];
        foreach ($keys as $key) {
            $this->checkKey($key);
            $values[$key] = $this->get($key, $default);
        }

        return $values;
    }

    /**
     * @param iterable<string, mixed> $values Values by key.
     * @param \DateInterval|int|null $ttl Time to live.
     * @return bool
     */
    public function setMultiple(iterable $values, null|int|DateInterval $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->checkKey($key);
            $this->set($key, $value, $ttl);
        }

        return true;
    }

    /**
     * @inheritDoc
     */
    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->checkKey($key);
            $this->delete($key);
        }

        return true;
    }

    /**
     * @inheritDoc
     */
    public function has(string $key): bool
    {
        $this->checkKey($key);
        if (!isset($this->items[$key])) {
            return false;
        }
        $expires = $this->items[$key][1];
        if ($expires !== null && $expires <= $this->clock->now()->getTimestamp()) {
            unset($this->items[$key]);

            return false;
        }

        return true;
    }

    /**
     * Rejects keys PSR-16 forbids.
     *
     * @throws \CakeDC\OAuth\Server\Testing\InvalidCacheKey
     */
    private function checkKey(mixed $key): void
    {
        if (!is_string($key) || $key === '' || strlen($key) > 64 || strpbrk($key, '{}()/\\@:') !== false) {
            throw new InvalidCacheKey('Invalid cache key.');
        }
    }
}
