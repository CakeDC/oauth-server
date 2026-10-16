<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\RateLimit;

use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\RateLimit\RateLimiter;
use CakeDC\OAuth\Server\Testing\ArrayCache;
use CakeDC\OAuth\Server\Testing\FrozenClock;
use PHPUnit\Framework\TestCase;

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
}
