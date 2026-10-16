<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Http\Handler;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Event\AuthorizationDenied;
use CakeDC\OAuth\Server\Event\ConsentGranted;
use CakeDC\OAuth\Server\Grant\Pkce;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\RawPathUri;
use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\UriInterface;

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
        $client = $this->harness->registeredClient(['name' => 'Claude']);
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
        $client = $this->harness->registeredClient();
        $this->harness->users->blocked = ['42'];
        $this->harness->signIn();

        $response = $this->harness->server->authorizeHandler()->handle($this->harness->request('GET', $this->harness->authorizeUrl($client)));

        $this->assertSame('access_denied', ServerHarness::redirectParams($response)['error']);
        $this->assertSame('not_allowed', $this->harness->events->ofType(AuthorizationDenied::class)[0]->reason);
    }

    public function testScopesBeyondTheOwnerAreDropped(): void
    {
        $client = $this->harness->registeredClient();
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
        $client = $this->harness->registeredClient();
        $this->harness->signIn();

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
        $client = $this->harness->registeredClient();
        $this->harness->signIn();
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
        $client = $this->harness->registeredClient();
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

    public function testASignedInPostWithARedirectableErrorForAnUntrustedClientGetsTheNotice(): void
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

        $this->assertSame('', $response->getHeaderLine('Location'));
        $html = (string)$response->getBody();
        $this->assertStringContainsString('Continue to app.example.com', $html);
    }

    public function testDeletingAConsentMakesTheClientUntrustedAgain(): void
    {
        $client = $this->harness->publicClient();
        $this->harness->authorizationCode($client, ['scope' => 'content:read']);
        $url = $this->harness->authorizeUrl($client, ['code_challenge_method' => 'plain']);
        $trusted = $this->harness->server->authorizeHandler()->handle($this->harness->request('GET', $url));
        $this->assertSame('invalid_request', ServerHarness::redirectParams($trusted)['error']);

        $this->harness->storage->deleteConsent('42', $client->id, Fixtures::MCP);

        $after = $this->harness->server->authorizeHandler()->handle($this->harness->request('GET', $url));
        $this->assertSame('', $after->getHeaderLine('Location'));
        $this->assertStringContainsString('Continue to app.example.com', (string)$after->getBody());
    }

    public function testADynamicClientIsHeadlinedByItsRedirectHostNotByItsName(): void
    {
        $client = $this->harness->publicClient(['name' => 'claude.ai']);
        $this->harness->signIn();

        $html = (string)$this->harness->server->authorizeHandler()->handle(
            $this->harness->request('GET', $this->harness->authorizeUrl($client)),
        )->getBody();

        $this->assertStringContainsString('<title>Authorize app.example.com</title>', $html);
        $this->assertStringContainsString('<h1>app.example.com wants to access Example MCP</h1>', $html);
    }

    public function testRedirectErrorsOfThePostAreIssuedWith303(): void
    {
        $client = $this->harness->registeredClient();
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

    /**
     * @return array<string, string>
     */
    private function consentFields(
        Client $client,
        array $params = [],
    ): array {
        $page = $this->harness->server->authorizeHandler()->handle(
            $this->harness->request('GET', $this->harness->authorizeUrl($client, $params)),
        );
        $this->assertSame(200, $page->getStatusCode());

        return ServerHarness::formFields((string)$page->getBody());
    }

    public function testARememberedConsentDoesNotCoverOfflineAccess(): void
    {
        $client = $this->harness->publicClient();
        $this->harness->authorizationCode($client, ['scope' => 'content:read']);

        $again = $this->harness->server->authorizeHandler()->handle(
            $this->harness->request('GET', $this->harness->authorizeUrl($client, ['scope' => 'content:read offline_access'])),
        );
        $this->assertSame(200, $again->getStatusCode());
        $this->assertStringContainsString('Stay connected', (string)$again->getBody());

        $this->harness->authorizationCode($client, ['scope' => 'content:read offline_access']);
        $covered = $this->harness->server->authorizeHandler()->handle(
            $this->harness->request('GET', $this->harness->authorizeUrl($client, ['scope' => 'content:read offline_access'])),
        );
        $this->assertSame(302, $covered->getStatusCode());
    }

    public function testAMetadataDocumentClientIsHeadlinedByItsHost(): void
    {
        $id = 'https://evil.example/client.json';
        $this->harness->dns->answers['evil.example'] = ['93.184.216.35'];
        $this->harness->transport->serve($id, [
            'client_id' => $id,
            'client_name' => 'Claude',
            'redirect_uris' => ['https://evil.example/cb'],
            'token_endpoint_auth_method' => 'none',
        ]);
        $stub = Fixtures::client(['clientId' => $id, 'redirectUris' => ['https://evil.example/cb']]);
        $this->harness->signIn();

        $html = (string)$this->harness->server->authorizeHandler()->handle(
            $this->harness->request('GET', $this->harness->authorizeUrl($stub)),
        )->getBody();

        $this->assertStringContainsString('<h1>evil.example wants to access Example MCP</h1>', $html);
        $this->assertStringContainsString('<title>Authorize evil.example</title>', $html);
        $this->assertStringNotContainsString('<h1>Claude', $html);
    }

    /**
     * With a PSR-7 implementation that returns `//evil.example/...` from getPath() (Guzzle, Laminas), the
     * login return URL and the form action still start with a single slash.
     */
    public function testARawDoubleSlashPathNeverBecomesAProtocolRelativeReturnUrl(): void
    {
        $client = $this->harness->publicClient();
        $url = $this->harness->authorizeUrl($client);
        $request = $this->harness->request('GET', $url)
            ->withUri(new RawPathUri($url, '//evil.example/authorize'), true);

        $this->harness->server->authorizeHandler()->handle($request);

        $returnTo = (string)$this->harness->userContext->returnTo;
        $this->assertStringStartsWith('/evil.example/authorize?', $returnTo);
        $this->assertStringStartsNotWith('//', $returnTo);

        $this->harness->signIn();
        $html = (string)$this->harness->server->authorizeHandler()->handle($request)->getBody();
        $this->assertStringContainsString('action="/evil.example/authorize"', $html);
    }

    public function testDoubleSlashPathsAreNormalised(): void
    {
        $client = $this->harness->publicClient();
        $url = str_replace('/oauth/authorize', '//evil.example/authorize', $this->harness->authorizeUrl($client));

        $this->harness->server->authorizeHandler()->handle($this->harness->request('GET', $url));
        $this->assertStringStartsWith('/evil.example/authorize?', (string)$this->harness->userContext->returnTo);

        $this->harness->signIn();
        $html = (string)$this->harness->server->authorizeHandler()->handle(
            $this->harness->request('GET', $url),
        )->getBody();
        $this->assertStringContainsString('action="/evil.example/authorize"', $html);
    }

    public function testBackslashPathsAreRefused(): void
    {
        $client = $this->harness->publicClient();
        $uri = $this->createStub(UriInterface::class);
        $uri->method('getPath')->willReturn('/\\evil.example/authorize');
        $uri->method('getQuery')->willReturn(
            (string)parse_url($this->harness->authorizeUrl($client), PHP_URL_QUERY),
        );
        $request = $this->harness->request('GET', 'https://example.com/oauth/authorize')->withUri($uri);

        $response = $this->harness->server->authorizeHandler()->handle($request);

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('', $response->getHeaderLine('Location'));
    }

    public function testTheTokenIsBoundToTheScopesShown(): void
    {
        $client = $this->harness->publicClient();
        $this->harness->users->scopes['42'] = ['content:read'];
        $this->harness->signIn();
        $fields = $this->consentFields($client, ['scope' => 'content:read content:publish']);

        $this->harness->users->scopes['42'] = null;
        $response = $this->harness->server->authorizeHandler()->handle(
            $this->harness->form('https://example.com/oauth/authorize', $fields + ['decision' => 'approve']),
        );

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('', $response->getHeaderLine('Location'));
        $this->assertCount(0, $this->harness->events->ofType(ConsentGranted::class));
    }

    public function testRepeatedUnrelatedNamesAreIgnoredOnGet(): void
    {
        $client = $this->harness->publicClient();
        $this->harness->signIn();

        $response = $this->harness->server->authorizeHandler()->handle(
            $this->harness->request('GET', $this->harness->authorizeUrl($client) . '&x=1&x=2'),
        );

        $this->assertSame(200, $response->getStatusCode());
    }

    public function testTheOfflineLineFollowsTheRefreshTokenMode(): void
    {
        $always = new ServerHarness();
        $client = $always->publicClient();
        $always->signIn();
        $html = (string)$always->server->authorizeHandler()->handle(
            $always->request('GET', $always->authorizeUrl($client)),
        )->getBody();
        $this->assertStringContainsString('Stay connected', $html);

        $onDemand = new ServerHarness(['refreshTokens' => 'offline_access']);
        $client = $onDemand->publicClient();
        $onDemand->signIn();
        $without = (string)$onDemand->server->authorizeHandler()->handle(
            $onDemand->request('GET', $onDemand->authorizeUrl($client)),
        )->getBody();
        $this->assertStringNotContainsString('Stay connected', $without);
        $with = (string)$onDemand->server->authorizeHandler()->handle(
            $onDemand->request('GET', $onDemand->authorizeUrl($client, ['scope' => 'content:read offline_access'])),
        )->getBody();
        $this->assertStringContainsString('Stay connected', $with);
    }

    public function testTheOfflineLineIsHiddenWhenTheClientCannotRefresh(): void
    {
        $client = $this->harness->publicClient(['grantTypes' => ['authorization_code']]);
        $this->harness->signIn();

        $html = (string)$this->harness->server->authorizeHandler()->handle(
            $this->harness->request('GET', $this->harness->authorizeUrl($client)),
        )->getBody();

        $this->assertStringContainsString('wants to access', $html);
        $this->assertStringNotContainsString('Stay connected', $html);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function badStates(): array
    {
        return ['invalid utf-8' => ["ab\xFFcd"], 'newline' => ["ab\ncd"], 'tab' => ["a\tb"]];
    }

    #[DataProvider('badStates')]
    public function testAStateOutsideVschardIsARedirectableErrorWithoutEchoingIt(string $state): void
    {
        $client = $this->harness->registeredClient();
        $this->harness->signIn();

        $response = $this->harness->server->authorizeHandler()->handle(
            $this->harness->request('GET', $this->harness->authorizeUrl($client, ['state' => $state])),
        );

        $this->assertSame(302, $response->getStatusCode());
        $params = ServerHarness::redirectParams($response);
        $this->assertSame('invalid_request', $params['error']);
        $this->assertArrayNotHasKey('state', $params);
        $this->assertSame('https://example.com', $params['iss']);
        $this->assertStringStartsWith($client->redirectUris[0], $response->getHeaderLine('Location'));
    }

    public function testAClientIdentityIsNotAPersonWhoCanConsent(): void
    {
        $client = $this->harness->publicClient();
        $this->harness->userContext->owner = new ResourceOwner('robot', 'Robot', null, SubjectType::Client);

        $response = $this->harness->server->authorizeHandler()->handle(
            $this->harness->request('GET', $this->harness->authorizeUrl($client)),
        );

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('', $response->getHeaderLine('Location'));
        $this->assertStringContainsString('Only people can authorize applications.', (string)$response->getBody());
        $this->assertSame([], $this->harness->events->ofType(ConsentGranted::class));
    }

    public function testForgedPostsHaveNoSideEffects(): void
    {
        $client = $this->harness->publicClient();
        $this->harness->signIn();
        $fields = $this->consentFields($client);
        unset($fields['consent_token']);

        foreach (['approve', 'deny'] as $decision) {
            $response = $this->harness->server->authorizeHandler()->handle(
                $this->harness->form('https://example.com/oauth/authorize', $fields + ['decision' => $decision]),
            );
            $this->assertSame(400, $response->getStatusCode());
            $this->assertSame('', $response->getHeaderLine('Location'));
        }
        $this->assertCount(0, $this->harness->events->ofType(AuthorizationDenied::class));
        $this->assertCount(0, $this->harness->events->ofType(ConsentGranted::class));
    }

    public function testATokenForAnotherOwnerHasNoLocation(): void
    {
        $client = $this->harness->publicClient();
        $this->harness->signIn();
        $fields = $this->consentFields($client);
        $this->harness->signIn('43');

        $response = $this->harness->server->authorizeHandler()->handle(
            $this->harness->form('https://example.com/oauth/authorize', $fields + ['decision' => 'approve']),
        );

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('', $response->getHeaderLine('Location'));
        $this->assertCount(0, $this->harness->events->ofType(ConsentGranted::class));
    }

    public function testPutIsNotAllowed(): void
    {
        $response = $this->harness->server->authorizeHandler()->handle(
            $this->harness->request('PUT', 'https://example.com/oauth/authorize'),
        );

        $this->assertSame(405, $response->getStatusCode());
    }

    public function testAMissingOrUnknownDecisionIsADenial(): void
    {
        $client = $this->harness->publicClient();
        $this->harness->signIn();
        $fields = $this->consentFields($client);

        foreach ([$fields, $fields + ['decision' => 'maybe']] as $post) {
            $response = $this->harness->server->authorizeHandler()->handle(
                $this->harness->form('https://example.com/oauth/authorize', $post),
            );
            $this->assertSame(303, $response->getStatusCode());
            $this->assertSame('access_denied', ServerHarness::redirectParams($response)['error']);
        }
    }

    public function testAnUnregisteredRedirectUriGetsThePageAndNoRedirect(): void
    {
        $client = $this->harness->publicClient();
        $this->harness->signIn();

        $response = $this->harness->server->authorizeHandler()->handle($this->harness->request(
            'GET',
            $this->harness->authorizeUrl($client, ['redirect_uri' => 'https://evil.example/cb']),
        ));

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('', $response->getHeaderLine('Location'));
    }

    public function testAPostWithoutTokenIsRefusedEvenWithARememberedConsent(): void
    {
        $client = $this->harness->publicClient();
        $this->harness->authorizationCode($client);

        $response = $this->harness->server->authorizeHandler()->handle($this->harness->form(
            'https://example.com/oauth/authorize',
            ['decision' => 'approve'] + [
                'response_type' => 'code',
                'client_id' => $client->clientId,
                'redirect_uri' => $client->redirectUris[0],
                'state' => 'st4te',
                'code_challenge' => Pkce::challengeFor(ServerHarness::VERIFIER),
                'code_challenge_method' => 'S256',
                'scope' => 'content:write',
                'resource' => Fixtures::MCP,
            ],
        ));

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('', $response->getHeaderLine('Location'));
    }

    public function testAnOwnerBlockedBetweenGetAndPostIsDenied(): void
    {
        $client = $this->harness->registeredClient();
        $this->harness->signIn();
        $fields = $this->consentFields($client);
        $this->harness->users->blocked = ['42'];

        $response = $this->harness->server->authorizeHandler()->handle(
            $this->harness->form('https://example.com/oauth/authorize', $fields + ['decision' => 'approve']),
        );

        $this->assertSame(303, $response->getStatusCode());
        $params = ServerHarness::redirectParams($response);
        $this->assertSame('access_denied', $params['error']);
        $this->assertSame('https://example.com', $params['iss']);
        $denied = $this->harness->events->ofType(AuthorizationDenied::class);
        $this->assertCount(1, $denied);
        $this->assertSame('not_allowed', $denied[0]->reason);
    }

    public function testControlCharactersInThePathAreRefused(): void
    {
        $client = $this->harness->publicClient();
        $uri = $this->createStub(UriInterface::class);
        $uri->method('getPath')->willReturn("/\t/evil.example/authorize");
        $uri->method('getQuery')->willReturn(
            (string)parse_url($this->harness->authorizeUrl($client), PHP_URL_QUERY),
        );
        $request = $this->harness->request('GET', 'https://example.com/oauth/authorize')->withUri($uri);

        $response = $this->harness->server->authorizeHandler()->handle($request);

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('', $response->getHeaderLine('Location'));
    }
}
