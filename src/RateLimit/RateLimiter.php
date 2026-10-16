<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\RateLimit;

use CakeDC\OAuth\Server\Exception\OAuthException;
use InvalidArgumentException;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Psr\SimpleCache\CacheInterface;
use Throwable;

/**
 * Fixed-window request counting per endpoint and key (the client IP). Counting is not atomic across
 * processes; under load a few extra requests may pass, which is acceptable for abuse control. Without a
 * cache nothing is limited, and when the cache fails the request is let through (abuse control, not a
 * quota) with a warning in the log.
 *
 * IPv6 addresses are counted per /64, the smallest block a subscriber usually gets, so rotating addresses
 * inside it does not reset the count. IPv4 addresses, also when written as IPv4-mapped IPv6
 * (`::ffff:203.0.113.7`), are counted one by one.
 *
 * @internal Built through the AuthorizationServer; configure it with the `rateLimit` settings.
 */
final class RateLimiter
{
    private LoggerInterface $logger;

    /**
     * @param \Psr\SimpleCache\CacheInterface|null $cache Counter storage; null disables limiting.
     * @param \Psr\Clock\ClockInterface $clock Clock.
     * @param array<string, array{0: int, 1: int}> $limits Endpoint => [max requests, window seconds].
     * @param \Psr\Log\LoggerInterface|null $logger Where a cache failure is reported.
     */
    public function __construct(
        private readonly ?CacheInterface $cache,
        private readonly ClockInterface $clock,
        private readonly array $limits,
        ?LoggerInterface $logger = null,
    ) {
        foreach ($limits as $endpoint => [$max, $window]) {
            if ($max < 1 || $window < 1) {
                throw new InvalidArgumentException("Rate limit for `{$endpoint}` must be at least 1 per 1 second.");
            }
        }
        $this->logger = $logger ?? new NullLogger();
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
        // PSR-16 only guarantees 64 characters: a short prefix and 160 bits of the digest.
        $digest = hash('sha256', $endpoint . "\n" . self::bucket($key) . "\n" . $start);
        $cacheKey = 'oauth_rl_' . substr($digest, 0, 40);
        try {
            $count = (int)$this->cache->get($cacheKey, 0) + 1;
            $this->cache->set($cacheKey, $count, $window);
        } catch (Throwable $e) {
            $this->logger->warning(
                'Rate limiting is off for this request: the cache failed ({message}).',
                ['message' => $e->getMessage(), 'exception' => $e, 'endpoint' => $endpoint],
            );

            return;
        }
        if ($count > $max) {
            throw OAuthException::rateLimited($start + $window - $now);
        }
    }

    /**
     * The bucket of $key: the /64 prefix of an IPv6 address, the IPv4 address of an IPv4-mapped one, any
     * other key as it is.
     */
    private static function bucket(string $key): string
    {
        $literal = str_starts_with($key, '[') && str_ends_with($key, ']') ? substr($key, 1, -1) : $key;
        if (!str_contains($literal, ':') || filter_var($literal, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
            return $key;
        }
        $binary = (string)inet_pton($literal);
        if (str_starts_with($binary, str_repeat("\0", 10) . "\xFF\xFF")) {
            return (string)inet_ntop(substr($binary, 12));
        }

        return bin2hex(substr($binary, 0, 8)) . '::/64';
    }
}
