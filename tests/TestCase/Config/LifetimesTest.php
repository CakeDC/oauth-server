<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Config;

use CakeDC\OAuth\Server\Config\Lifetimes;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

class LifetimesTest extends TestCase
{
    public function testDefaults(): void
    {
        $lifetimes = new Lifetimes();

        $this->assertSame([60, 3600, 2592000, 31536000, 7776000, 30], [
            $lifetimes->code, $lifetimes->access, $lifetimes->refresh,
            $lifetimes->family, $lifetimes->personalMax, $lifetimes->refreshReuseGrace,
        ]);
    }

    public function testFromArrayOverridesSomeValues(): void
    {
        $lifetimes = Lifetimes::fromArray(['access' => 600, 'refreshReuseGrace' => 0]);

        $this->assertSame(600, $lifetimes->access);
        $this->assertSame(0, $lifetimes->refreshReuseGrace);
        $this->assertSame(60, $lifetimes->code);
    }

    public function testRejectsUnknownKeysAndNonPositiveValues(): void
    {
        try {
            Lifetimes::fromArray(['acess' => 600]);
            $this->fail('Unknown key accepted');
        } catch (InvalidArgumentException $e) {
            $this->assertStringContainsString('acess', $e->getMessage());
        }
        $this->expectException(InvalidArgumentException::class);
        new Lifetimes(access: 0);
    }

    public function testRejectsNonIntegerValuesAndNegativeGrace(): void
    {
        try {
            Lifetimes::fromArray(['access' => '600']);
            $this->fail('String accepted');
        } catch (InvalidArgumentException $e) {
            $this->assertStringContainsString('integer', $e->getMessage());
        }
        $this->expectException(InvalidArgumentException::class);
        new Lifetimes(refreshReuseGrace: -1);
    }
}
