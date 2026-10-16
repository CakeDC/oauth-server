<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Security;

use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

/**
 * RFC 9700, "Clickjacking": no page of the server can be framed.
 */
class ClickjackingTest extends TestCase
{
    private function assertNotFramable(ResponseInterface $response): void
    {
        $this->assertSame('DENY', $response->getHeaderLine('X-Frame-Options'));
        $this->assertStringContainsString("frame-ancestors 'none'", $response->getHeaderLine('Content-Security-Policy'));
    }

    public function testConsentConnectionsAndErrorPages(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $harness->signIn();
        $authorize = $harness->server->authorizeHandler();

        $this->assertNotFramable($authorize->handle($harness->request('GET', $harness->authorizeUrl($client))));
        $connections = $harness->server->connectionsHandler();
        $this->assertNotFramable($connections->handle($harness->request('GET', 'https://example.com/oauth/connections')));
        $this->assertNotFramable($authorize->handle($harness->request('GET', 'https://example.com/oauth/authorize?client_id=nobody')));
    }
}
