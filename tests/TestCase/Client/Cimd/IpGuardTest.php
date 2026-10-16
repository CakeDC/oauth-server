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
            'ipv4 compatible' => ['::127.0.0.1', false],
            'ipv4 compatible hex' => ['::a9fe:a9fe', false],
            'translated' => ['::ffff:0:7f00:1', false],
            'v6 5f00' => ['5f00::1', false],
            'v6 3fff documentation' => ['3fff::1', false],
            'nat64 local' => ['64:ff9b:1::1', false],
            'discard' => ['100::1', false],
            'site local' => ['fec0::1', false],
            'teredo' => ['2001:0:4136:e378:8000:63bf:3fff:fdd2', false],
            'benchmark' => ['198.18.0.1', false],
            'ietf protocol' => ['192.0.0.1', false],
            'reserved' => ['240.0.0.1', false],
            'below 172.16' => ['172.15.255.255', true],
            'start of 172.16' => ['172.16.0.0', false],
            'below cgnat' => ['100.63.255.255', true],
            'start of cgnat' => ['100.64.0.0', false],
            'end of cgnat' => ['100.127.255.255', false],
            'after cgnat' => ['100.128.0.0', true],
            'just under fec0' => ['febf::1', false],
            'global v6' => ['2001:4860:4860::8888', true],
            'not an address' => ['example.com', false],
        ];
    }

    #[DataProvider('addresses')]
    public function testClassifiesAddresses(string $ip, bool $public): void
    {
        $this->assertSame($public, IpGuard::isPublic($ip));
    }
}
