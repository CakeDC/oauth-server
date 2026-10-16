<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\RateLimit;

use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\RateLimit\RateLimiter;
use CakeDC\OAuth\Server\Test\Support\BrokenCache;
use CakeDC\OAuth\Server\Test\Support\RecordingLogger;
use CakeDC\OAuth\Server\Testing\ArrayCache;
use CakeDC\OAuth\Server\Testing\FrozenClock;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;

class RateLimiterTest extends TestCase
{
    public function testAllowsUpToTheLimitPerWindowAndKey(): void
    {
        $clock = new FrozenClock();
        $limiter = new RateLimiter(new ArrayCache($clock), $clock, ['token' => [2, 60]]);

        $limiter->hit('token', '10.0.0.1');
        $limiter->hit('token', '10.0.0.1');
        $limiter->hit('token', '10.0.0.2');
        try {
            $limiter->hit('token', '10.0.0.1');
            $this->fail('Third request allowed');
        } catch (OAuthException $e) {
            $this->assertSame(429, $e->status);
            $this->assertSame(['Retry-After' => '60'], $e->headers);
        }

        $clock->advance(60);
        $limiter->hit('token', '10.0.0.1');
        $this->addToAssertionCount(1);
    }

    public function testEndpointsWithoutALimitAreFree(): void
    {
        $clock = new FrozenClock();
        $limiter = new RateLimiter(new ArrayCache($clock), $clock, []);
        $uncached = new RateLimiter(null, $clock, ['authorize' => [1, 60]]);

        for ($i = 0; $i < 100; $i++) {
            $limiter->hit('authorize', 'x');
            $uncached->hit('authorize', 'x');
        }
        $this->addToAssertionCount(1);
    }

    public function testRetryAfterReflectsTheTimeLeftInTheWindow(): void
    {
        $clock = new FrozenClock();
        $limiter = new RateLimiter(new ArrayCache($clock), $clock, ['token' => [1, 60]]);
        $limiter->hit('token', 'k');
        $clock->advance(37);

        try {
            $limiter->hit('token', 'k');
            $this->fail('Second request allowed');
        } catch (OAuthException $e) {
            $this->assertSame(['Retry-After' => '23'], $e->headers);
        }
    }

    public function testCanHitAgainAtTheExactNextWindowStart(): void
    {
        $clock = new FrozenClock();
        $limiter = new RateLimiter(new ArrayCache($clock), $clock, ['token' => [1, 60]]);
        $limiter->hit('token', 'k');
        $clock->advance(59);
        try {
            $limiter->hit('token', 'k');
            $this->fail('Still inside the window');
        } catch (OAuthException) {
            $clock->advance(1);
            $limiter->hit('token', 'k');
        }
        $this->addToAssertionCount(1);
    }

    public function testHostileKeysWorkWithAValidatingCache(): void
    {
        $clock = new FrozenClock();
        $limiter = new RateLimiter(new ArrayCache($clock), $clock, ['token' => [1, 60]]);
        $key = str_repeat("{}()/\\@:\n", 5000);

        $limiter->hit('token', $key);
        $this->expectException(OAuthException::class);
        $limiter->hit('token', $key);
    }

    public function testRejectsNonPositiveLimits(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new RateLimiter(null, new FrozenClock(), ['token' => [0, 60]]);
    }

    public function testRejectsNonPositiveWindows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new RateLimiter(null, new FrozenClock(), ['token' => [1, 0]]);
    }

    /**
     * Rate limiting is abuse control, not a quota: when the cache is down the request goes through, and
     * the failure is logged as a warning instead of turning every endpoint into a 500.
     */
    public function testACacheFailureLetsTheRequestThroughWithAWarning(): void
    {
        $cache = new BrokenCache();
        $logger = new RecordingLogger();
        $limiter = new RateLimiter($cache, new FrozenClock(), ['token' => [1, 60]], $logger);

        $limiter->hit('token', '10.0.0.1');
        $limiter->hit('token', '10.0.0.1');

        $this->assertGreaterThan(0, $cache->calls);
        $this->assertCount(2, $logger->records);
        $this->assertSame(LogLevel::WARNING, $logger->records[0][0]);
        $this->assertStringContainsString('Rate limiting', $logger->records[0][1]);
        $this->assertStringNotContainsString('10.0.0.1', $logger->text());
    }

    /**
     * @return array<string, array{string, string, bool}>
     */
    public static function addressPairs(): array
    {
        return [
            'same IPv6 /64' => ['2001:db8:1:2::1', '2001:db8:1:2:ffff:ffff:ffff:9', true],
            'same IPv6 /64, other spelling' => ['2001:DB8:1:2:0:0:0:1', '2001:db8:1:2::abcd', true],
            'other IPv6 /64' => ['2001:db8:1:2::1', '2001:db8:1:3::1', false],
            'IPv4 addresses' => ['203.0.113.7', '203.0.113.8', false],
            'IPv4-mapped addresses are IPv4' => ['::ffff:203.0.113.7', '::ffff:203.0.113.8', false],
            'IPv4-mapped is the same IPv4' => ['::ffff:203.0.113.7', '203.0.113.7', true],
            'bracketed IPv6' => ['[2001:db8:1:2::1]', '2001:db8:1:2::2', true],
            'not an address' => ['unknown', 'unknown', true],
        ];
    }

    /**
     * IPv6 addresses count per /64, the smallest block one subscriber usually gets; IPv4 addresses (also
     * when written as IPv4-mapped IPv6) count one by one.
     */
    #[DataProvider('addressPairs')]
    public function testIpv6AddressesShareTheBucketOfTheirSlash64(string $first, string $second, bool $shared): void
    {
        $clock = new FrozenClock();
        $limiter = new RateLimiter(new ArrayCache($clock), $clock, ['token' => [1, 60]]);
        $limiter->hit('token', $first);

        try {
            $limiter->hit('token', $second);
            $this->assertFalse($shared, 'The second address should share the first one\'s bucket.');
        } catch (OAuthException $e) {
            $this->assertSame(429, $e->status);
            $this->assertTrue($shared, 'The second address should have its own bucket.');
        }
    }
}
