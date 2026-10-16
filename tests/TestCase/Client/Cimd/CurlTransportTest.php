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
        try {
            (new CurlTransport())->get('https://pin.localhost:1/client.json', '127.0.0.1', 1, 100);
            $this->fail('The request succeeded');
        } catch (RuntimeException $e) {
            $this->assertStringNotContainsString('Only https URLs', $e->getMessage());
            $this->assertStringNotContainsString('could not be configured', $e->getMessage());
        }
    }

    public function testOptionsPinTheConnectionAndLockDownCurl(): void
    {
        $options = (new CurlTransport())->options('https://client.example:8443/c.json', '93.184.216.34', 4);

        $this->assertSame(['::93.184.216.34:8443'], $options[CURLOPT_CONNECT_TO]);
        $this->assertSame(['client.example:8443:93.184.216.34'], $options[CURLOPT_RESOLVE]);
        $this->assertSame('', $options[CURLOPT_PROXY]);
        $this->assertSame('*', $options[CURLOPT_NOPROXY]);
        $this->assertFalse($options[CURLOPT_FOLLOWLOCATION]);
        $this->assertSame(CURLPROTO_HTTPS, $options[CURLOPT_PROTOCOLS]);
        $this->assertSame(CURLPROTO_HTTPS, $options[CURLOPT_REDIR_PROTOCOLS]);
        $this->assertSame(4, $options[CURLOPT_CONNECTTIMEOUT]);
        $this->assertSame(4, $options[CURLOPT_TIMEOUT]);
        $this->assertTrue($options[CURLOPT_SSL_VERIFYPEER]);
        $this->assertSame(2, $options[CURLOPT_SSL_VERIFYHOST]);
        $this->assertArrayNotHasKey(CURLOPT_ENCODING, $options);
    }

    public function testIpv6PinsAreBracketed(): void
    {
        $options = (new CurlTransport())->options('https://client.example/c.json', '2606:4700::1111', 4);

        $this->assertSame(['::[2606:4700::1111]:443'], $options[CURLOPT_CONNECT_TO]);
    }

    public function testRefusesHostsCurlCouldNormalize(): void
    {
        $this->expectException(RuntimeException::class);

        (new CurlTransport())->options('https://x%41.attacker.example/c.json', '93.184.216.34', 4);
    }

    public function testWriterStopsAtTheLimit(): void
    {
        $body = '';
        $tooLarge = false;
        $write = CurlTransport::writer(10, $body, $tooLarge);

        $this->assertSame(6, $write(null, 'abcdef'));
        $this->assertSame(0, $write(null, 'ghijk'));
        $this->assertTrue($tooLarge);
        $this->assertSame('abcdef', $body);
    }
}
