<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\RateLimit;

use CakeDC\OAuth\Server\Exception\OAuthException;
use Psr\Clock\ClockInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * Fixed-window request counting per endpoint and key (usually the client IP). Counting is not atomic
 * across processes; under load a few extra requests may pass, which is acceptable for abuse control.
 * Without a cache nothing is limited.
 */
final class RateLimiter
{
    /**
     * @param \Psr\SimpleCache\CacheInterface|null $cache Counter storage; null disables limiting.
     * @param \Psr\Clock\ClockInterface $clock Clock.
     * @param array<string, array{0: int, 1: int}> $limits Endpoint => [max requests, window seconds].
     */
    public function __construct(
        private readonly ?CacheInterface $cache,
        private readonly ClockInterface $clock,
        private readonly array $limits,
    ) {
    }

    /**
     * Counts a request, failing once the window's limit is passed.
     *
     * @throws \CakeDC\OAuth\Server\Exception\OAuthException 429 when over the limit.
     */
    public function hit(string $endpoint, string $key): void
    {
        if ($this->cache === null || !isset($this->limits[$endpoint])) {
            return;
        }
        [$max, $window] = $this->limits[$endpoint];
        $now = $this->clock->now()->getTimestamp();
        $start = intdiv($now, $window) * $window;
        $cacheKey = 'oauth_rate_' . sha1($endpoint . "\n" . $key . "\n" . $start);
        $count = (int)$this->cache->get($cacheKey, 0) + 1;
        $this->cache->set($cacheKey, $count, $window);
        if ($count > $max) {
            throw OAuthException::rateLimited($start + $window - $now);
        }
    }
}
