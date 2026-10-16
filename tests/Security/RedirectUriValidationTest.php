<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Security;

use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9700, "Insufficient Redirect URI Validation": exact matching, loopback port only, no
 * dangerous schemes at registration, and nothing is sent to an unregistered URI.
 */
class RedirectUriValidationTest extends TestCase
{
    public function testAnUnregisteredRedirectNeverReceivesAnything(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $harness->signIn();

        $redirects = [
            'https://evil.example/cb',
            'https://app.example.com/cb/../evil',
            'https://app.example.com/cb?x=1',
            'https://app.example.com.evil.example/cb',
            'https://app.example.com:8443/cb',
            'http://app.example.com/cb',
        ];
        foreach ($redirects as $redirect) {
            $url = $harness->authorizeUrl($client, ['redirect_uri' => $redirect]);
            $response = $harness->server->authorizeHandler()->handle($harness->request('GET', $url));
            $this->assertSame(400, $response->getStatusCode(), $redirect);
            $this->assertSame('', $response->getHeaderLine('Location'), $redirect);
        }
    }

    public function testLoopbackMatchesOnlyThePort(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient(['redirectUris' => ['http://127.0.0.1/cb']]);
        $harness->signIn();

        $okUrl = $harness->authorizeUrl($client, ['redirect_uri' => 'http://127.0.0.1:4444/cb']);
        $otherUrl = $harness->authorizeUrl($client, ['redirect_uri' => 'http://localhost:4444/cb']);
        $ok = $harness->server->authorizeHandler()->handle($harness->request('GET', $okUrl));
        $other = $harness->server->authorizeHandler()->handle($harness->request('GET', $otherUrl));

        $this->assertSame(200, $ok->getStatusCode());
        $this->assertSame(400, $other->getStatusCode());
    }

    public function testRegistrationRefusesDangerousRedirects(): void
    {
        $harness = new ServerHarness();
        $uris = [
            'javascript:alert(1)',
            'https://app.example.com/cb#frag',
            'http://app.example.com/cb',
            'data:text/html,x',
            'file:///etc/passwd',
            'vbscript:msgbox(1)',
        ];
        foreach ($uris as $uri) {
            $body = (string)json_encode([
                'application_type' => 'native',
                'redirect_uris' => [$uri],
                'token_endpoint_auth_method' => 'none',
            ]);
            $response = $harness->server->registerHandler()->handle($harness->request(
                'POST',
                'https://example.com/oauth/register',
                ['Content-Type' => 'application/json'],
                $body,
            ));
            $this->assertSame('invalid_redirect_uri', $harness->json($response)['error'], $uri);
        }
    }

    public function testLoopbackStillNeedsTheSamePathAndQuery(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient(['redirectUris' => ['http://127.0.0.1/cb']]);
        $harness->signIn();

        foreach (['http://127.0.0.1:4444/other', 'http://127.0.0.1:4444/cb?x=1', 'https://127.0.0.1:4444/cb'] as $uri) {
            $url = $harness->authorizeUrl($client, ['redirect_uri' => $uri]);
            $response = $harness->server->authorizeHandler()->handle($harness->request('GET', $url));
            $this->assertSame(400, $response->getStatusCode(), $uri);
            $this->assertSame('', $response->getHeaderLine('Location'), $uri);
        }
    }
}
