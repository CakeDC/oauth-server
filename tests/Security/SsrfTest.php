<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Security;

use CakeDC\OAuth\Server\Client\Cimd\FetchedResponse;
use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use PHPUnit\Framework\TestCase;

/**
 * Server-side request forgery through Client ID Metadata Document URLs.
 */
class SsrfTest extends TestCase
{
    public function testInternalAddressesAreNeverFetched(): void
    {
        $harness = new ServerHarness();
        $harness->dns->answers['internal.example'] = ['10.0.0.8'];
        $harness->signIn();

        $response = $harness->server->authorizeHandler()->handle($harness->request(
            'GET',
            'https://example.com/oauth/authorize?response_type=code&client_id='
                . rawurlencode('https://internal.example/client.json'),
        ));

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame([], $harness->transport->requests);
    }

    public function testRedirectsFromTheMetadataHostAreNotFollowed(): void
    {
        $harness = new ServerHarness();
        $harness->transport->responses['https://client.example/client.json'] =
            new FetchedResponse(302, ['location' => 'http://169.254.169.254/'], '');
        $harness->signIn();

        $response = $harness->server->authorizeHandler()->handle($harness->request(
            'GET',
            'https://example.com/oauth/authorize?response_type=code&client_id='
                . rawurlencode('https://client.example/client.json'),
        ));

        $this->assertSame(400, $response->getStatusCode());
        $this->assertCount(1, $harness->transport->requests);
    }

    public function testPlainHttpClientIdUrlsAreNeverFetched(): void
    {
        $harness = new ServerHarness();
        $harness->transport->serve('http://client.example/client.json', ['client_id' => 'http://client.example/client.json']);
        $harness->signIn();

        $response = $harness->server->authorizeHandler()->handle($harness->request(
            'GET',
            'https://example.com/oauth/authorize?response_type=code&client_id='
                . rawurlencode('http://client.example/client.json'),
        ));

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame([], $harness->transport->requests);
    }
}
