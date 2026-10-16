<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Client\Cimd;

use CakeDC\OAuth\Server\Client\Cimd\CurlTransport;
use PHPUnit\Framework\TestCase;
use RuntimeException;

class CurlTransportTest extends TestCase
{
    public function testOnlyFetchesHttps(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('https');

        (new CurlTransport())->get('http://example.com/client.json', '93.184.216.34', 1, 100);
    }

    public function testRefusesUserinfoAndBackslashUrls(): void
    {
        foreach (['https://a@evil.example/x', 'https://a.example\\@evil.example/x'] as $url) {
            try {
                (new CurlTransport())->get($url, '93.184.216.34', 1, 100);
                $this->fail('Accepted ' . $url);
            } catch (RuntimeException $e) {
                $this->assertStringContainsString('https', $e->getMessage());
            }
        }
    }

    public function testNetworkErrorsBecomeExceptions(): void
    {
        $this->expectException(RuntimeException::class);

        (new CurlTransport())->get('https://localhost:1/client.json', '127.0.0.1', 1, 100);
    }
}
