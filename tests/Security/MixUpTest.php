<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Security;

use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9700, "Mix-Up Attacks": every authorization response names its issuer (RFC 9207).
 */
class MixUpTest extends TestCase
{
    public function testSuccessAndErrorResponsesCarryTheIssuer(): void
    {
        $harness = new ServerHarness();
        $client = $harness->registeredClient();
        $harness->signIn();
        $handler = $harness->server->authorizeHandler();

        $errorUrl = $harness->authorizeUrl($client, ['response_type' => 'token']);
        $error = $handler->handle($harness->request('GET', $errorUrl));
        $this->assertSame('https://example.com', ServerHarness::redirectParams($error)['iss']);

        $harness->authorizationCode($client);
        $success = $handler->handle($harness->request('GET', $harness->authorizeUrl($client)));
        $this->assertSame('https://example.com', ServerHarness::redirectParams($success)['iss']);

        $metadata = $harness->json($harness->server->metadataHandler()->handle($harness->request('GET', '/')));
        $this->assertTrue($metadata['authorization_response_iss_parameter_supported']);
    }

    public function testTheIssuerIsTheConfiguredOneNotTheRequestHost(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $harness->authorizationCode($client);
        $forwarded = ['X-Forwarded-Host' => 'evil.example', 'X-Forwarded-Proto' => 'http'];
        $evil = fn(string $url): string => str_replace('https://example.com', 'http://evil.example', $url);
        $handler = $harness->server->authorizeHandler();

        $error = $handler->handle($harness->request(
            'GET',
            $evil($harness->authorizeUrl($client, ['response_type' => 'token'])),
            $forwarded,
        ));
        $success = $handler->handle($harness->request('GET', $evil($harness->authorizeUrl($client)), $forwarded));

        $this->assertSame('https://example.com', ServerHarness::redirectParams($error)['iss']);
        $this->assertSame('https://example.com', ServerHarness::redirectParams($success)['iss']);
        $this->assertArrayHasKey('code', ServerHarness::redirectParams($success));

        $metadata = $harness->json($harness->server->metadataHandler()->handle($harness->request(
            'GET',
            'http://evil.example/.well-known/oauth-authorization-server',
            $forwarded,
        )));
        $this->assertSame('https://example.com', $metadata['issuer']);
        $this->assertSame('https://example.com/oauth/authorize', $metadata['authorization_endpoint']);
        $this->assertSame('https://example.com/oauth/token', $metadata['token_endpoint']);
    }

    public function testDenyAndErrorRedirectsCarryStateAndIssuer(): void
    {
        $harness = new ServerHarness();
        $client = $harness->registeredClient();
        $harness->signIn();
        $handler = $harness->server->authorizeHandler();

        $page = $handler->handle($harness->request('GET', $harness->authorizeUrl($client, ['scope' => 'content:publish'])));
        $fields = ServerHarness::formFields((string)$page->getBody()) + ['decision' => 'deny'];
        $deny = ServerHarness::redirectParams($handler->handle($harness->form('https://example.com/oauth/authorize', $fields)));
        $this->assertSame('access_denied', $deny['error']);
        $this->assertSame('st4te', $deny['state']);
        $this->assertSame('https://example.com', $deny['iss']);

        $error = ServerHarness::redirectParams($handler->handle($harness->request(
            'GET',
            $harness->authorizeUrl($client, ['response_type' => 'token']),
        )));
        $this->assertSame('st4te', $error['state']);
        $this->assertSame('https://example.com', $error['iss']);
    }
}
