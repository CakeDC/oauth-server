<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Client\Cimd;

use CakeDC\OAuth\Server\Client\Cimd\FetchedResponse;
use CakeDC\OAuth\Server\Client\Cimd\MetadataDocumentFetcher;
use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Test\Support\FakeDns;
use CakeDC\OAuth\Server\Test\Support\FakeTransport;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;

class MetadataDocumentFetcherTest extends TestCase
{
    private const URL = 'https://client.example/oauth/client.json';

    private FakeDns $dns;

    private FakeTransport $transport;

    protected function setUp(): void
    {
        $this->dns = new FakeDns();
        $this->transport = new FakeTransport();
    }

    /**
     * @return array<string, mixed>
     */
    private function document(array $changes = []): array
    {
        return $changes + [
            'client_id' => self::URL,
            'client_name' => 'Example',
            'redirect_uris' => ['https://client.example/cb'],
            'token_endpoint_auth_method' => 'none',
        ];
    }

    private function fetcher(?array $allowedHosts = null): MetadataDocumentFetcher
    {
        return new MetadataDocumentFetcher($this->dns, $this->transport, 5, 10240, $allowedHosts);
    }

    private function assertRejected(string $message, ?string $clientId = null, ?array $allowedHosts = null): void
    {
        try {
            $this->fetcher($allowedHosts)->fetch($clientId ?? self::URL);
            $this->fail('The document was accepted');
        } catch (OAuthException $e) {
            $this->assertSame('invalid_client', $e->error);
            $this->assertStringContainsString($message, $e->getMessage());
        }
    }

    public function testFetchesAValidDocumentFromTheValidatedAddress(): void
    {
        $this->transport->serve(self::URL, $this->document(), 'public, max-age=600');

        $result = $this->fetcher()->fetch(self::URL);

        $this->assertSame('Example', $result['document']['client_name']);
        $this->assertSame(600, $result['maxAge']);
        $this->assertSame([[self::URL, '93.184.216.34']], $this->transport->requests);
    }

    public function testCacheHeaders(): void
    {
        $this->transport->serve(self::URL, $this->document(), 'no-store');
        $this->assertSame(0, $this->fetcher()->fetch(self::URL)['maxAge']);

        $this->transport->responses[self::URL] = new FetchedResponse(
            200,
            ['content-type' => 'application/json'],
            (string)json_encode($this->document()),
        );
        $this->assertNull($this->fetcher()->fetch(self::URL)['maxAge']);
    }

    public function testIdentifiesMetadataDocumentIds(): void
    {
        $this->assertTrue(
            MetadataDocumentFetcher::isMetadataDocumentId('https://claude.ai/oauth/mcp-oauth-client-metadata'),
        );
        $this->assertFalse(MetadataDocumentFetcher::isMetadataDocumentId('3f2a9c'));
        $this->assertFalse(MetadataDocumentFetcher::isMetadataDocumentId('https://client.example\\@evil.example/x'));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function badUrls(): array
    {
        return [
            'http' => ['http://client.example/client.json'],
            'no path' => ['https://client.example'],
            'root path' => ['https://client.example/'],
            'fragment' => ['https://client.example/client.json#x'],
            'credentials' => ['https://user:pass@client.example/client.json'],
            'userinfo trick' => ['https://client.example@169.254.169.254/client.json'],
            'backslash' => ['https://client.example\\@evil.example/client.json'],
            'space' => ['https://client.example/a b.json'],
            'newline' => ["https://client.example/client.json\n"],
            'control char' => ["https://client.example/\x00client.json"],
            'percent-encoded host' => ['https://x%41.attacker.example/client.json'],
            'decimal host' => ['https://2130706433/x'],
            'hex host' => ['https://0x7f.0.0.1/x'],
            'trailing dot' => ['https://client.example./client.json'],
            'single label' => ['https://localhost/client.json'],
            'dot segment' => ['https://client.example/a/../client.json'],
            'encoded dot segment' => ['https://client.example/a/%2e%2e/client.json'],
            'non-ascii host' => ['https://clíent.example/client.json'],
        ];
    }

    #[DataProvider('badUrls')]
    public function testRejectsBadUrls(string $url): void
    {
        $this->assertRejected('not a valid metadata document URL', $url);
    }

    public function testHonoursTheHostAllowlist(): void
    {
        $this->assertRejected('not accepted', null, ['claude.ai']);
        $this->transport->serve(self::URL, $this->document());
        $this->fetcher(['Client.example'])->fetch(self::URL);
        $this->addToAssertionCount(1);
    }

    public function testRejectsHostsResolvingToPrivateOrMixedAddresses(): void
    {
        $this->dns->answers['client.example'] = ['10.0.0.5'];
        $this->assertRejected('non-public address');
        $this->dns->answers['client.example'] = ['93.184.216.34', '127.0.0.1'];
        $this->assertRejected('non-public address');
        $this->dns->answers['client.example'] = [];
        $this->assertRejected('does not resolve');
        $this->assertSame([], $this->transport->requests);
    }

    /**
     * A resolver that fails (a timeout, SERVFAIL) gave no answer: the failure is temporary, like a network
     * error, and says nothing about the client. Only an answer without addresses means "does not resolve".
     */
    public function testAFailedLookupIsATemporaryFailure(): void
    {
        $this->dns->failing = ['client.example'];

        try {
            $this->fetcher()->fetch(self::URL);
            $this->fail('A client was accepted without a lookup.');
        } catch (OAuthException $e) {
            $this->assertSame('invalid_client', $e->error);
            $this->assertTrue($e->temporary);
            $this->assertStringNotContainsString('temporary server error', $e->getMessage());
        }
        $this->assertSame([], $this->transport->requests);

        $this->dns->failing = [];
        $this->dns->answers['client.example'] = [];
        try {
            $this->fetcher()->fetch(self::URL);
            $this->fail('A client that does not resolve was accepted.');
        } catch (OAuthException $e) {
            $this->assertFalse($e->temporary);
        }
    }

    public function testRejectsPrivateAddressLiterals(): void
    {
        $this->assertRejected('non-public address', 'https://[::1]/x');
        $this->assertRejected('non-public address', 'https://[::ffff:127.0.0.1]/x');
        $this->assertRejected('non-public address', 'https://169.254.169.254/latest/meta-data');
    }

    public function testAllowlistIsNotFooledBySimilarHosts(): void
    {
        $this->dns->answers['evil-client.example'] = ['93.184.216.34'];
        $this->dns->answers['a.client.example'] = ['93.184.216.34'];
        $this->assertRejected('not accepted', 'https://evil-client.example/c.json', ['client.example']);
        $this->assertRejected('not accepted', 'https://a.client.example/c.json', ['client.example']);
    }

    public function testRejectsJsonpAndAcceptsParameters(): void
    {
        $this->transport->responses[self::URL] = new FetchedResponse(
            200,
            ['content-type' => 'application/jsonp'],
            (string)json_encode($this->document()),
        );
        $this->assertRejected('application/json');
        $this->transport->responses[self::URL] = new FetchedResponse(
            200,
            ['content-type' => ' Application/JSON ; charset=utf-8'],
            (string)json_encode($this->document()),
        );
        $this->assertSame('Example', $this->fetcher()->fetch(self::URL)['document']['client_name']);
    }

    public function testSMaxAgeIsNotMaxAge(): void
    {
        $this->transport->serve(self::URL, $this->document(), 's-maxage=999');
        $this->assertNull($this->fetcher()->fetch(self::URL)['maxAge']);
        $this->transport->serve(self::URL, $this->document(), 'public, s-maxage=9, max-age=42');
        $this->assertSame(42, $this->fetcher()->fetch(self::URL)['maxAge']);
    }

    public function testTransportErrorsAreGeneric(): void
    {
        $this->transport->responses[self::URL] = new RuntimeException('internal curl detail');
        try {
            $this->fetcher()->fetch(self::URL);
            $this->fail('Accepted');
        } catch (OAuthException $e) {
            $this->assertStringNotContainsString('internal', $e->getMessage());
        }
    }

    public function testRejectsNonPositiveLimits(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new MetadataDocumentFetcher($this->dns, $this->transport, 0);
    }

    public function testRejectsBadResponses(): void
    {
        $this->transport->responses[self::URL] = new FetchedResponse(302, ['location' => 'https://10.0.0.1/'], '');
        $this->assertRejected('HTTP 302');
        $this->transport->responses[self::URL] = new FetchedResponse(200, ['content-type' => 'text/html'], '<html>');
        $this->assertRejected('application/json');
        $this->transport->responses[self::URL] = new FetchedResponse(
            200,
            ['content-type' => 'application/json'],
            '[1,2]',
        );
        $this->assertRejected('JSON object');
        $this->transport->responses[self::URL] = new RuntimeException('The document is larger than 10240 bytes.');
        $this->assertRejected('could not be fetched');
    }

    /**
     * @return array<string, array{array<string, mixed>, string}>
     */
    public static function badDocuments(): array
    {
        return [
            'other client_id' => [['client_id' => 'https://evil.example/client.json'], 'does not match'],
            'no name' => [['client_name' => ' '], 'client_name'],
            'no redirects' => [['redirect_uris' => []], 'redirect_uris'],
            'redirect not a string' => [['redirect_uris' => [42]], 'redirect_uris'],
            'confidential' => [['token_endpoint_auth_method' => 'private_key_jwt'], 'public'],
        ];
    }

    #[DataProvider('badDocuments')]
    public function testValidatesTheDocument(array $changes, string $message): void
    {
        $this->transport->serve(self::URL, $this->document($changes));

        $this->assertRejected($message);
    }
}
