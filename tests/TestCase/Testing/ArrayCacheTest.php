<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Testing;

use CakeDC\OAuth\Server\Testing\ArrayCache;
use CakeDC\OAuth\Server\Testing\FrozenClock;
use CakeDC\OAuth\Server\Testing\InvalidCacheKey;
use DateInterval;
use PHPUnit\Framework\Attributes\DataProvider;
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

    /**
     * @return array<string, array{0: mixed}>
     */
    public static function badKeys(): array
    {
        $keys = ['empty' => ''];
        foreach (str_split('{}()/\\@:') as $char) {
            $keys['char ' . $char] = ['a' . $char . 'b'];
        }

        return array_map(fn($k) => is_array($k) ? $k : [$k], $keys);
    }

    #[DataProvider('badKeys')]
    public function testRejectsInvalidKeysEverywhere(string $key): void
    {
        $cache = new ArrayCache(new FrozenClock());
        $calls = [
            fn() => $cache->get($key),
            fn() => $cache->set($key, 1),
            fn() => $cache->delete($key),
            fn() => $cache->has($key),
            fn() => $cache->getMultiple([$key]),
            fn() => $cache->setMultiple([$key => 1]),
            fn() => $cache->deleteMultiple([$key]),
        ];
        foreach ($calls as $i => $call) {
            try {
                $call();
                $this->fail("Call {$i} accepted key");
            } catch (InvalidCacheKey) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testRejectsNonStringKeysInMultipleMethods(): void
    {
        $cache = new ArrayCache(new FrozenClock());
        $this->expectException(InvalidCacheKey::class);
        $cache->getMultiple([1]);
    }

    public function testRejectsNonStringKeysInSetAndDeleteMultiple(): void
    {
        $cache = new ArrayCache(new FrozenClock());
        try {
            $cache->setMultiple([1 => 'v']);
            $this->fail('setMultiple accepted int key');
        } catch (InvalidCacheKey) {
            $this->addToAssertionCount(1);
        }
        $this->expectException(InvalidCacheKey::class);
        $cache->deleteMultiple([2]);
    }
}
