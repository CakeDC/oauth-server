<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Testing;

use CakeDC\OAuth\Server\Testing\ArrayCache;
use CakeDC\OAuth\Server\Testing\FrozenClock;
use DateInterval;
use PHPUnit\Framework\TestCase;

class ArrayCacheTest extends TestCase
{
    public function testStoresWithTimeToLive(): void
    {
        $clock = new FrozenClock();
        $cache = new ArrayCache($clock);

        $cache->set('a', 1, 10);
        $cache->set('b', 2, new DateInterval('PT20S'));
        $cache->set('c', 3);
        $this->assertSame(1, $cache->get('a'));
        $this->assertTrue($cache->has('b'));

        $clock->advance(10);
        $this->assertNull($cache->get('a'));
        $this->assertSame('x', $cache->get('a', 'x'));
        $this->assertSame(2, $cache->get('b'));
        $this->assertSame(['b' => 2, 'c' => 3, 'z' => null], $cache->getMultiple(['b', 'c', 'z']));

        $cache->delete('c');
        $this->assertFalse($cache->has('c'));
        $cache->clear();
        $this->assertFalse($cache->has('b'));
    }
}
