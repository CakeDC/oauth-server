<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Security;

use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9700, "Open Redirection": the server never redirects to a URI it has not validated, and the
 * login return URL is relative.
 */
class OpenRedirectTest extends TestCase
{
    public function testInvalidClientsAndRedirectsAreNotFollowed(): void
    {
        $harness = new ServerHarness();
        $response = $harness->server->authorizeHandler()->handle($harness->request(
            'GET',
            'https://example.com/oauth/authorize?client_id=nobody&redirect_uri=https%3A%2F%2Fevil.example&response_type=token',
        ));

        $this->assertSame('', $response->getHeaderLine('Location'));
    }

    public function testTheLoginReturnUrlIsRelative(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();

        $harness->server->authorizeHandler()->handle($harness->request('GET', $harness->authorizeUrl($client)));

        $this->assertStringStartsWith('/oauth/authorize?', (string)$harness->userContext->returnTo);
    }
}
