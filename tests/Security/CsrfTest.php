<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Security;

use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9700, "Cross-Site Request Forgery": state round-trips unchanged, and consent decisions need a
 * form token bound to the request and to the person.
 */
class CsrfTest extends TestCase
{
    public function testAConsentDecisionNeedsItsOwnFormToken(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $harness->signIn();
        $handler = $harness->server->authorizeHandler();
        $page = $handler->handle($harness->request('GET', $harness->authorizeUrl($client)));
        $fields = ServerHarness::formFields((string)$page->getBody()) + ['decision' => 'approve'];
        $this->assertArrayHasKey('consent_token', $fields);

        $without = $fields;
        unset($without['consent_token']);
        $this->assertSame(400, $handler->handle($harness->form('https://example.com/oauth/authorize', $without))->getStatusCode());

        $harness->signIn('43');
        $this->assertSame(400, $handler->handle($harness->form('https://example.com/oauth/authorize', $fields))->getStatusCode());
    }

    public function testStateComesBackUnchanged(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $harness->authorizationCode($client);
        $state = 'a b+c/d=e&f';

        $url = $harness->authorizeUrl($client, ['state' => $state]);
        $response = $harness->server->authorizeHandler()->handle($harness->request('GET', $url));

        $this->assertSame($state, ServerHarness::redirectParams($response)['state']);
    }

    public function testTamperingWithTheConsentFieldsIsRefused(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $harness->signIn();
        $handler = $harness->server->authorizeHandler();
        $page = $handler->handle($harness->request('GET', $harness->authorizeUrl($client)));
        $fields = ServerHarness::formFields((string)$page->getBody()) + ['decision' => 'approve'];

        foreach (['scope' => 'content:publish', 'redirect_uri' => 'https://evil.example/cb'] as $name => $value) {
            $response = $handler->handle($harness->form(
                'https://example.com/oauth/authorize',
                [$name => $value] + $fields,
            ));
            $this->assertSame(400, $response->getStatusCode(), $name);
            $this->assertSame('', $response->getHeaderLine('Location'), $name);
        }
    }
}
