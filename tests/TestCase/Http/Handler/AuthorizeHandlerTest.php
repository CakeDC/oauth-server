<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Http\Handler;

use CakeDC\OAuth\Server\Event\AuthorizationDenied;
use CakeDC\OAuth\Server\Event\ConsentGranted;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use PHPUnit\Framework\TestCase;

class AuthorizeHandlerTest extends TestCase
{
    private ServerHarness $harness;

    protected function setUp(): void
    {
        $this->harness = new ServerHarness();
    }

    public function testAnonymousVisitorsGoToTheLoginAndComeBack(): void
    {
        $client = $this->harness->publicClient();
        $url = $this->harness->authorizeUrl($client);

        $response = $this->harness->server->authorizeHandler()->handle($this->harness->request('GET', $url));

        $this->assertSame(302, $response->getStatusCode());
        $this->assertSame(substr($url, strlen('https://example.com')), $this->harness->userContext->returnTo);
    }

    public function testShowsTheConsentPage(): void
    {
        $client = $this->harness->publicClient(['name' => 'Claude']);
        $this->harness->signIn();

        $response = $this->harness->server->authorizeHandler()->handle(
            $this->harness->request('GET', $this->harness->authorizeUrl($client)),
        );
        $html = (string)$response->getBody();

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('DENY', $response->getHeaderLine('X-Frame-Options'));
        $this->assertStringContainsString('Claude wants to access Example MCP', $html);
        $this->assertStringContainsString('Edit drafts', $html);
        $this->assertStringContainsString('action="/oauth/authorize"', $html);
        $fields = ServerHarness::formFields($html);
        $this->assertSame($client->clientId, $fields['client_id']);
        $this->assertArrayHasKey('consent_token', $fields);
    }

    public function testApprovingRedirectsWithCodeStateAndIssuer(): void
    {
        $client = $this->harness->publicClient();

        $code = $this->harness->authorizationCode($client);

        $this->assertNotNull($this->harness->storage->findCodeByHash(TokenGenerator::hash($code)));
        $this->assertCount(1, $this->harness->events->ofType(ConsentGranted::class));
    }

    public function testTheConsentPostRedirectsWith303(): void
    {
        $client = $this->harness->publicClient();
        $this->harness->signIn();
        $page = $this->harness->server->authorizeHandler()->handle($this->harness->request('GET', $this->harness->authorizeUrl($client)));
        $fields = ServerHarness::formFields((string)$page->getBody()) + ['decision' => 'approve'];

        $response = $this->harness->server->authorizeHandler()->handle($this->harness->form('https://example.com/oauth/authorize', $fields));

        $this->assertSame(303, $response->getStatusCode());
        $params = ServerHarness::redirectParams($response);
        $this->assertSame('st4te', $params['state']);
        $this->assertSame('https://example.com', $params['iss']);
        $this->assertStringStartsWith('https://app.example.com/cb?', $response->getHeaderLine('Location'));
    }

    public function testARememberedConsentSkipsThePage(): void
    {
        $client = $this->harness->publicClient();
        $this->harness->authorizationCode($client);

        $response = $this->harness->server->authorizeHandler()->handle(
            $this->harness->request('GET', $this->harness->authorizeUrl($client, ['state' => 'again'])),
        );

        $this->assertSame(302, $response->getStatusCode());
        $this->assertSame('again', ServerHarness::redirectParams($response)['state']);
        $this->assertArrayHasKey('code', ServerHarness::redirectParams($response));

        $more = $this->harness->server->authorizeHandler()->handle(
            $this->harness->request('GET', $this->harness->authorizeUrl($client, ['scope' => 'content:publish'])),
        );
        $this->assertSame(200, $more->getStatusCode());
    }

    public function testDenying(): void
    {
        $client = $this->harness->publicClient();
        $this->harness->signIn();
        $page = $this->harness->server->authorizeHandler()->handle($this->harness->request('GET', $this->harness->authorizeUrl($client)));
        $fields = ServerHarness::formFields((string)$page->getBody()) + ['decision' => 'deny'];

        $response = $this->harness->server->authorizeHandler()->handle($this->harness->form('https://example.com/oauth/authorize', $fields));

        $this->assertSame(303, $response->getStatusCode());
        $this->assertSame('access_denied', ServerHarness::redirectParams($response)['error']);
        $this->assertSame('user_denied', $this->harness->events->ofType(AuthorizationDenied::class)[0]->reason);
    }

    public function testATamperedOrExpiredConsentFormIsRefused(): void
    {
        $client = $this->harness->publicClient();
        $this->harness->signIn();
        $page = $this->harness->server->authorizeHandler()->handle($this->harness->request('GET', $this->harness->authorizeUrl($client)));
        $fields = ServerHarness::formFields((string)$page->getBody()) + ['decision' => 'approve'];

        $tampered = $this->harness->server->authorizeHandler()->handle(
            $this->harness->form('https://example.com/oauth/authorize', ['scope' => 'content:publish'] + $fields),
        );
        $this->assertSame(400, $tampered->getStatusCode());
        $this->assertStringContainsString('consent form', (string)$tampered->getBody());

        $this->harness->clock->advance(901);
        $expired = $this->harness->server->authorizeHandler()->handle($this->harness->form('https://example.com/oauth/authorize', $fields));
        $this->assertSame(400, $expired->getStatusCode());
    }

    public function testAPostWithoutSessionShowsAnError(): void
    {
        $client = $this->harness->publicClient();
        $this->harness->signIn();
        $page = $this->harness->server->authorizeHandler()->handle($this->harness->request('GET', $this->harness->authorizeUrl($client)));
        $fields = ServerHarness::formFields((string)$page->getBody()) + ['decision' => 'approve'];
        $this->harness->userContext->owner = null;

        $response = $this->harness->server->authorizeHandler()->handle($this->harness->form('https://example.com/oauth/authorize', $fields));

        $this->assertSame(403, $response->getStatusCode());
        $this->assertStringContainsString('session', (string)$response->getBody());
    }

    public function testOwnersTheApplicationRefusesAreDenied(): void
    {
        $client = $this->harness->publicClient();
        $this->harness->users->blocked = ['42'];
        $this->harness->signIn();

        $response = $this->harness->server->authorizeHandler()->handle($this->harness->request('GET', $this->harness->authorizeUrl($client)));

        $this->assertSame('access_denied', ServerHarness::redirectParams($response)['error']);
        $this->assertSame('not_allowed', $this->harness->events->ofType(AuthorizationDenied::class)[0]->reason);
    }

    public function testScopesBeyondTheOwnerAreDropped(): void
    {
        $client = $this->harness->publicClient();
        $this->harness->users->scopes['42'] = ['content:read'];
        $this->harness->signIn();

        $page = $this->harness->server->authorizeHandler()->handle(
            $this->harness->request('GET', $this->harness->authorizeUrl($client, ['scope' => 'content:read content:publish'])),
        );
        $this->assertStringContainsString('Read your posts', (string)$page->getBody());
        $this->assertStringNotContainsString('Publish posts', (string)$page->getBody());

        $none = $this->harness->server->authorizeHandler()->handle(
            $this->harness->request('GET', $this->harness->authorizeUrl($client, ['scope' => 'content:publish'])),
        );
        $this->assertSame('invalid_scope', ServerHarness::redirectParams($none)['error']);
    }

    public function testInvalidClientsGetAPageAndNoRedirect(): void
    {
        $this->harness->signIn();

        $response = $this->harness->server->authorizeHandler()->handle(
            $this->harness->request('GET', 'https://example.com/oauth/authorize?client_id=nobody&redirect_uri=https%3A%2F%2Fevil.example%2F'),
        );

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('', $response->getHeaderLine('Location'));
        $this->assertStringContainsString('invalid_client', (string)$response->getBody());
    }

    public function testRedirectableErrorsCarryStateAndIssuer(): void
    {
        $client = $this->harness->publicClient();

        $response = $this->harness->server->authorizeHandler()->handle(
            $this->harness->request('GET', $this->harness->authorizeUrl($client, ['code_challenge_method' => 'plain'])),
        );

        $params = ServerHarness::redirectParams($response);
        $this->assertSame('invalid_request', $params['error']);
        $this->assertSame('st4te', $params['state']);
        $this->assertSame('https://example.com', $params['iss']);
    }

    public function testRepeatedParametersAreRejected(): void
    {
        $client = $this->harness->publicClient();
        $url = $this->harness->authorizeUrl($client) . '&scope=content:publish';

        $response = $this->harness->server->authorizeHandler()->handle($this->harness->request('GET', $url));

        $this->assertSame('invalid_request', ServerHarness::redirectParams($response)['error']);
    }

    public function testRateLimited(): void
    {
        $harness = new ServerHarness(['rateLimit' => ['authorize' => [2, 60]]]);
        $client = $harness->publicClient();
        $url = $harness->authorizeUrl($client);

        $harness->server->authorizeHandler()->handle($harness->request('GET', $url));
        $harness->server->authorizeHandler()->handle($harness->request('GET', $url));
        $response = $harness->server->authorizeHandler()->handle($harness->request('GET', $url));

        $this->assertSame(429, $response->getStatusCode());
        $this->assertSame('60', $response->getHeaderLine('Retry-After'));
    }

    public function testDefaultsWhenTheClientSendsNoResourceOrScope(): void
    {
        $client = $this->harness->publicClient();

        $code = $this->harness->authorizationCode($client, ['resource' => null, 'scope' => null]);

        $stored = $this->harness->storage->findCodeByHash(TokenGenerator::hash($code));
        $this->assertSame(Fixtures::MCP, $stored?->resource);
        $this->assertSame(['content:read'], $stored?->scopes);
    }

    public function testEveryRedirectCarriesTheIssuer(): void
    {
        $client = $this->harness->publicClient();
        $this->harness->signIn();
        $cases = [
            ['response_type' => 'token'],
            ['scope' => 'nope:nope'],
            ['code_challenge' => null],
        ];
        foreach ($cases as $override) {
            $response = $this->harness->server->authorizeHandler()->handle(
                $this->harness->request('GET', $this->harness->authorizeUrl($client, $override)),
            );
            $params = ServerHarness::redirectParams($response);
            $this->assertArrayHasKey('error', $params);
            $this->assertSame('https://example.com', $params['iss']);
            $this->assertSame('st4te', $params['state']);
        }
        $this->harness->users->scopes['42'] = ['content:read'];
        $none = $this->harness->server->authorizeHandler()->handle(
            $this->harness->request('GET', $this->harness->authorizeUrl($client, ['scope' => 'content:publish'])),
        );
        $this->assertSame('invalid_scope', ServerHarness::redirectParams($none)['error']);
        $this->assertSame('https://example.com', ServerHarness::redirectParams($none)['iss']);
    }

    public function testApprovalRedirectsCarryTheIssuer(): void
    {
        $client = $this->harness->publicClient();
        $this->harness->authorizationCode($client);

        $response = $this->harness->server->authorizeHandler()->handle(
            $this->harness->request('GET', $this->harness->authorizeUrl($client)),
        );

        $this->assertSame('https://example.com', ServerHarness::redirectParams($response)['iss']);
    }

    public function testAForgedPostWithoutTokenGetsNoRedirectAndNoSideEffects(): void
    {
        $client = $this->harness->publicClient();
        $this->harness->signIn();
        $fields = ServerHarness::formFields((string)$this->harness->server->authorizeHandler()->handle(
            $this->harness->request('GET', $this->harness->authorizeUrl($client)),
        )->getBody());
        unset($fields['consent_token']);

        $response = $this->harness->server->authorizeHandler()->handle(
            $this->harness->form('https://example.com/oauth/authorize', $fields + ['decision' => 'approve']),
        );

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('', $response->getHeaderLine('Location'));
        $this->assertCount(0, $this->harness->events->ofType(ConsentGranted::class));
    }

    public function testATokenIssuedForAnotherOwnerIsRefused(): void
    {
        $client = $this->harness->publicClient();
        $this->harness->signIn();
        $fields = ServerHarness::formFields((string)$this->harness->server->authorizeHandler()->handle(
            $this->harness->request('GET', $this->harness->authorizeUrl($client)),
        )->getBody());
        $other = array_key_last($this->harness->users->users);
        $this->assertNotSame('42', $other);
        $this->harness->signIn((string)$other);

        $response = $this->harness->server->authorizeHandler()->handle(
            $this->harness->form('https://example.com/oauth/authorize', $fields + ['decision' => 'approve']),
        );

        $this->assertSame(400, $response->getStatusCode());
    }

    public function testRedirectErrorsOfThePostAreIssuedWith303(): void
    {
        $client = $this->harness->publicClient();
        $this->harness->signIn();
        $fields = ['state' => 'st4te', 'response_type' => 'token'] + [
            'client_id' => $client->clientId,
            'redirect_uri' => $client->redirectUris[0],
        ];

        $response = $this->harness->server->authorizeHandler()->handle(
            $this->harness->form('https://example.com/oauth/authorize', $fields),
        );

        $this->assertSame(303, $response->getStatusCode());
        $this->assertSame('https://example.com', ServerHarness::redirectParams($response)['iss']);
    }
}
