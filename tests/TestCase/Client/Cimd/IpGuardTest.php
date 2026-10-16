<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Client\Cimd;

use CakeDC\OAuth\Server\Client\Cimd\IpGuard;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class IpGuardTest extends TestCase
{
    /**
     * @return array<string, array{string, bool}>
     */
    public static function addresses(): array
    {
        return [
            'google dns' => ['8.8.8.8', true],
            'anthropic' => ['160.79.104.10', true],
            'cloudflare v6' => ['2606:4700:4700::1111', true],
            'just outside 172.16/12' => ['172.32.0.1', true],
            'just outside cgnat' => ['100.128.0.1', true],
            'private 10' => ['10.1.2.3', false],
            'private 172' => ['172.31.255.255', false],
            'private 192.168' => ['192.168.1.1', false],
            'loopback' => ['127.0.0.1', false],
            'cloud metadata' => ['169.254.169.254', false],
            'cgnat' => ['100.64.0.1', false],
            'this network' => ['0.0.0.0', false],
            'multicast' => ['224.0.0.1', false],
            'broadcast' => ['255.255.255.255', false],
            'documentation' => ['203.0.113.5', false],
            'v6 loopback' => ['::1', false],
            'v6 unspecified' => ['::', false],
            'v4 mapped' => ['::ffff:8.8.8.8', false],
            'unique local' => ['fd12::1', false],
            'link local' => ['fe80::1', false],
            'v6 multicast' => ['ff02::1', false],
            'v6 documentation' => ['2001:db8::1', false],
            '6to4' => ['2002:808:808::1', false],
            'nat64' => ['64:ff9b::808:808', false],
            'not an address' => ['example.com', false],
        ];
    }

    #[DataProvider('addresses')]
    public function testClassifiesAddresses(string $ip, bool $public): void
    {
        $this->assertSame($public, IpGuard::isPublic($ip));
    }
}
