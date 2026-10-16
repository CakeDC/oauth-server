<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Support;

use CakeDC\OAuth\Server\Support\HostClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class HostClassTest extends TestCase
{
    /**
     * @return array<string, array{string, bool}>
     */
    public static function hosts(): array
    {
        return [
            'localhost' => ['localhost', true],
            'uppercase' => ['LocalHost', true],
            'trailing dot' => ['localhost.', true],
            '.localhost name' => ['app.localhost', true],
            'loopback' => ['127.0.0.1', true],
            'loopback range' => ['127.9.9.9', true],
            'bracketed IPv6 loopback' => ['[::1]', true],
            'IPv6 loopback' => ['::1', true],
            'IPv6 loopback, long form' => ['[0:0:0:0:0:0:0:1]', true],
            'IPv4-mapped loopback' => ['[::ffff:127.0.0.1]', true],
            'IPv4-mapped loopback, hex' => ['[::ffff:7f00:1]', true],
            'unspecified IPv4' => ['0.0.0.0', true],
            'this network' => ['0.1.2.3', true],
            'unspecified IPv6' => ['[::]', true],
            'bare unspecified IPv6' => ['::', true],
            'IPv4-mapped unspecified' => ['[::ffff:0.0.0.0]', true],
            'a host name' => ['app.example.com', false],
            'a name that ends like localhost' => ['notlocalhost', false],
            'a name with localhost inside' => ['localhost.example.com', false],
            'public IPv4' => ['203.0.113.5', false],
            'private IPv4' => ['192.168.1.5', false],
            'public IPv6' => ['[2606:4700:4700::1111]', false],
            'IPv4-mapped public' => ['[::ffff:203.0.113.5]', false],
            'empty' => ['', false],
        ];
    }

    #[DataProvider('hosts')]
    public function testThisComputer(string $host, bool $expected): void
    {
        $this->assertSame($expected, HostClass::isThisComputer($host));
    }

    public function testTheLoopbackLiteralsAreTheFourOfRfc8252(): void
    {
        foreach (['localhost', 'LOCALHOST', '127.0.0.1', '[::1]', '::1'] as $host) {
            $this->assertTrue(HostClass::isLoopbackLiteral($host), $host);
        }
        foreach (['127.0.0.5', '0.0.0.0', 'app.localhost', '[::]', 'example.com'] as $host) {
            $this->assertFalse(HostClass::isLoopbackLiteral($host), $host);
        }
    }

    /**
     * @return array<string, array{string, bool, string}>
     */
    public static function redirects(): array
    {
        return [
            'remote https' => ['https://App.Example.com/cb', false, 'app.example.com'],
            'https localhost' => ['https://localhost:8443/cb', true, 'localhost'],
            'https unspecified' => ['https://0.0.0.0/cb', true, '0.0.0.0'],
            'https unspecified IPv6' => ['https://[::]/cb', true, '[::]'],
            'http loopback' => ['http://127.0.0.1:51000/cb', true, '127.0.0.1'],
            'http remote (never registrable)' => ['http://app.example.com/cb', true, 'app.example.com'],
            'private scheme' => ['com.example.app:/cb', true, 'com.example.app:'],
            'private scheme with authority' => ['com.example.app://oauth/cb', true, 'com.example.app:'],
            'uppercase private scheme' => ['Cursor://anysphere/cb', true, 'cursor:'],
            'private scheme named like a host' => ['claude.ai:/callback', true, 'claude.ai:'],
        ];
    }

    #[DataProvider('redirects')]
    public function testRedirects(string $uri, bool $onThisComputer, string $target): void
    {
        $this->assertSame($onThisComputer, HostClass::redirectStaysOnThisComputer($uri), $uri);
        $this->assertSame($target, HostClass::redirectTarget($uri), $uri);
    }

    public function testAnUnparseableRedirectIsItsOwnTarget(): void
    {
        $this->assertSame('nonsense', HostClass::redirectTarget('nonsense'));
        $this->assertTrue(HostClass::redirectStaysOnThisComputer('nonsense'));
    }
}
