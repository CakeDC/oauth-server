<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Security;

use CakeDC\OAuth\Server\AuthorizationServer;
use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Client\ClientType;
use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use CakeDC\OAuth\Server\View\ErrorPageRendererInterface;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9700, "Open Redirection" (section 4.11.2): the server never redirects to a URI it has not
 * validated, never redirects before the person is authenticated, sends errors back automatically only
 * to redirect URIs it trusts, and the login return URL is relative.
 */
class OpenRedirectTest extends TestCase
{
    private const EVIL = 'https://evil.example/login';

    public function testInvalidClientsAndRedirectsAreNotFollowed(): void
    {
        $harness = new ServerHarness();
        $response = $harness->server->authorizeHandler()->handle($harness->request(
            'GET',
            'https://example.com/oauth/authorize?client_id=nobody&redirect_uri=https%3A%2F%2Fevil.example&response_type=token',
        ));

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('', $response->getHeaderLine('Location'));
        $this->assertStringNotContainsString('evil.example', (string)$response->getBody());
    }

    public function testTheLoginReturnUrlIsRelative(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();

        $harness->server->authorizeHandler()->handle($harness->request('GET', $harness->authorizeUrl($client)));

        $this->assertStringStartsWith('/oauth/authorize?', (string)$harness->userContext->returnTo);
    }

    public function testAnAnonymousVisitorIsSentToTheLoginInsteadOfAnAttackerRegisteredUri(): void
    {
        $harness = new ServerHarness();
        $clientId = $this->registerDynamic($harness, ['token_endpoint_auth_method' => 'none']);
        $url = 'https://example.com/oauth/authorize?client_id=' . $clientId
            . '&redirect_uri=' . rawurlencode(self::EVIL) . '&response_type=x';

        $response = $harness->server->authorizeHandler()->handle($harness->request('GET', $url));

        $this->assertNull($harness->userContext->owner);
        $this->assertSame(302, $response->getStatusCode());
        $this->assertStringStartsWith('/login?redirect=', $response->getHeaderLine('Location'));
        $this->assertSame(substr($url, strlen('https://example.com')), $harness->userContext->returnTo);

        // Back from the login, the request is validated again; the client is still not trusted.
        $harness->signIn();
        $again = $harness->server->authorizeHandler()->handle(
            $harness->request('GET', 'https://example.com' . $harness->userContext->returnTo),
        );
        $this->assertSame(400, $again->getStatusCode());
        $this->assertSame('', $again->getHeaderLine('Location'));
        $this->assertStringStartsWith(self::EVIL . '?error=', $this->continueLink((string)$again->getBody()));
    }

    public function testAMetadataDocumentWithRegistrationClosedCannotBounceAnonymousVisitors(): void
    {
        $harness = new ServerHarness(['registration' => ['mode' => 'closed']]);
        $clientId = 'https://client.example/c.json';
        $harness->transport->serve($clientId, [
            'client_id' => $clientId,
            'client_name' => 'Anything',
            'redirect_uris' => ['https://client.example/phish'],
            'token_endpoint_auth_method' => 'none',
        ]);

        // No code_challenge: a redirectable error.
        $response = $harness->server->authorizeHandler()->handle($harness->request(
            'GET',
            'https://example.com/oauth/authorize?client_id=' . rawurlencode($clientId)
                . '&redirect_uri=' . rawurlencode('https://client.example/phish') . '&response_type=code',
        ));

        $this->assertSame(302, $response->getStatusCode());
        $this->assertStringStartsWith('/login?redirect=', $response->getHeaderLine('Location'));
        $this->assertStringStartsWith('/oauth/authorize?', (string)$harness->userContext->returnTo);
    }

    public function testAnAnonymousPostWithARedirectableErrorGetsThePage(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient(['type' => ClientType::Registered]);

        $response = $harness->server->authorizeHandler()->handle($harness->form('https://example.com/oauth/authorize', [
            'client_id' => $client->clientId,
            'redirect_uri' => $client->redirectUris[0],
            'response_type' => 'token',
            'state' => 'st4te',
        ]));

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('', $response->getHeaderLine('Location'));
        $this->assertNull($harness->userContext->returnTo);
    }

    public function testAClientIdentityGetsThePageInsteadOfTheRedirect(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient(['type' => ClientType::Registered]);
        $harness->userContext->owner = new ResourceOwner('robot', 'Robot', null, SubjectType::Client);

        $response = $harness->server->authorizeHandler()->handle(
            $harness->request('GET', $harness->authorizeUrl($client, ['response_type' => 'token'])),
        );

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('', $response->getHeaderLine('Location'));
        $this->assertNull($harness->userContext->returnTo);
    }

    public function testASignedInPersonIsShownWhereAnUntrustedClientWouldSendThem(): void
    {
        // Dynamic registration makes a confidential client by default: a secret proves nothing about
        // who chose the redirect URI.
        foreach (['public' => ['token_endpoint_auth_method' => 'none'], 'confidential' => []] as $kind => $extra) {
            $harness = new ServerHarness();
            $clientId = $this->registerDynamic($harness, $extra);
            $harness->signIn();

            $response = $harness->server->authorizeHandler()->handle($harness->request(
                'GET',
                'https://example.com/oauth/authorize?client_id=' . $clientId
                    . '&redirect_uri=' . rawurlencode(self::EVIL) . '&response_type=x&state=st4te',
            ));
            $html = (string)$response->getBody();

            $this->assertSame(400, $response->getStatusCode(), $kind);
            $this->assertSame('', $response->getHeaderLine('Location'), $kind);
            $this->assertStringContainsString('evil.example', $html, $kind);
            $link = $this->continueLink($html);
            $this->assertStringStartsWith(self::EVIL . '?error=unsupported_response_type', $link, $kind);
            parse_str((string)parse_url($link, PHP_URL_QUERY), $params);
            $this->assertSame('st4te', $params['state'], $kind);
            $this->assertSame('https://example.com', $params['iss'], $kind);
            $this->assertSame('DENY', $response->getHeaderLine('X-Frame-Options'), $kind);
        }
    }

    public function testAMetadataDocumentClientWithoutConsentIsNotTrustedEither(): void
    {
        $harness = new ServerHarness();
        $clientId = 'https://client.example/c.json';
        $harness->transport->serve($clientId, [
            'client_id' => $clientId,
            'client_name' => 'Anything',
            'redirect_uris' => ['https://client.example/phish'],
            'token_endpoint_auth_method' => 'none',
        ]);
        $harness->signIn();

        $response = $harness->server->authorizeHandler()->handle($harness->request(
            'GET',
            'https://example.com/oauth/authorize?client_id=' . rawurlencode($clientId)
                . '&redirect_uri=' . rawurlencode('https://client.example/phish') . '&response_type=code',
        ));

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('', $response->getHeaderLine('Location'));
        $this->assertStringStartsWith('https://client.example/phish?error=invalid_request', $this->continueLink((string)$response->getBody()));
    }

    public function testAnErrorGoesBackToAClientThePersonAlreadyApproved(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        // A consent for another resource is enough: the person accepted this client before.
        $harness->authorizationCode($client, ['resource' => Fixtures::API, 'scope' => 'api']);

        $response = $harness->server->authorizeHandler()->handle(
            $harness->request('GET', $harness->authorizeUrl($client, ['response_type' => 'token'])),
        );

        $this->assertSame(302, $response->getStatusCode());
        $this->assertStringStartsWith(
            'https://app.example.com/cb?error=unsupported_response_type',
            $response->getHeaderLine('Location'),
        );
    }

    public function testAConsentForAnotherClientDoesNotVouchForThisOne(): void
    {
        $harness = new ServerHarness();
        $harness->authorizationCode($harness->publicClient());
        $client = $this->dynamicClient($harness);

        $response = $harness->server->authorizeHandler()->handle(
            $harness->request('GET', $harness->authorizeUrl($client, ['response_type' => 'token'])),
        );

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('', $response->getHeaderLine('Location'));
    }

    public function testAnErrorGoesBackToAClientAnAdministratorRegistered(): void
    {
        $harness = new ServerHarness();
        $harness->signIn();
        $clients = [
            'public' => $harness->publicClient(['type' => ClientType::Registered]),
            'confidential' => $harness->confidentialClient(),
        ];
        foreach ($clients as $kind => $client) {
            $response = $harness->server->authorizeHandler()->handle(
                $harness->request('GET', $harness->authorizeUrl($client, ['code_challenge' => null])),
            );

            $this->assertSame(302, $response->getStatusCode(), $kind);
            $this->assertStringStartsWith(
                'https://app.example.com/cb?error=invalid_request',
                $response->getHeaderLine('Location'),
                $kind,
            );
        }
    }

    public function testDenyingStillRedirectsToAnUntrustedClient(): void
    {
        $harness = new ServerHarness();
        $client = $this->dynamicClient($harness);
        $harness->signIn();
        $page = $harness->server->authorizeHandler()->handle($harness->request('GET', $harness->authorizeUrl($client)));
        $fields = ServerHarness::formFields((string)$page->getBody()) + ['decision' => 'deny'];

        $response = $harness->server->authorizeHandler()->handle(
            $harness->form('https://example.com/oauth/authorize', $fields),
        );

        $this->assertSame(303, $response->getStatusCode());
        $this->assertStringStartsWith(self::EVIL . '?error=access_denied', $response->getHeaderLine('Location'));
    }

    public function testAnUntrustedClientTheApplicationRefusesGetsThePage(): void
    {
        $harness = new ServerHarness();
        $client = $this->dynamicClient($harness);
        $harness->users->blocked = ['42'];
        $harness->signIn();

        $response = $harness->server->authorizeHandler()->handle(
            $harness->request('GET', $harness->authorizeUrl($client)),
        );

        $this->assertSame(403, $response->getStatusCode());
        $this->assertSame('', $response->getHeaderLine('Location'));
        $this->assertStringStartsWith(self::EVIL . '?error=access_denied', $this->continueLink((string)$response->getBody()));
    }

    public function testACustomErrorRendererWithoutTheNoticeShowsThePlainPage(): void
    {
        $harness = new ServerHarness();
        $renderer = new class implements ErrorPageRendererInterface {
            public function render(OAuthException $error): string
            {
                return 'custom:' . $error->error;
            }
        };
        $server = new AuthorizationServer(
            Fixtures::config(),
            $harness->storage,
            $harness->users,
            $harness->userContext,
            $harness->factory,
            $harness->factory,
            clock: $harness->clock,
            transport: $harness->transport,
            dns: $harness->dns,
            errorPageRenderer: $renderer,
        );
        $client = $this->dynamicClient($harness);
        $harness->signIn();

        $response = $server->authorizeHandler()->handle(
            $harness->request('GET', $harness->authorizeUrl($client, ['response_type' => 'token'])),
        );

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('', $response->getHeaderLine('Location'));
        $this->assertSame('custom:unsupported_response_type', (string)$response->getBody());
    }

    /**
     * Registers a client for https://evil.example/login through dynamic registration.
     *
     * @param array<string, mixed> $extra More metadata.
     */
    private function registerDynamic(ServerHarness $harness, array $extra = []): string
    {
        $registered = $harness->json($harness->server->registerHandler()->handle($harness->request(
            'POST',
            'https://example.com/oauth/register',
            ['Content-Type' => 'application/json'],
            (string)json_encode($extra + ['client_name' => 'Totally legit', 'redirect_uris' => [self::EVIL]]),
        )));
        $this->assertArrayHasKey('client_id', $registered);

        return (string)$registered['client_id'];
    }

    private function dynamicClient(ServerHarness $harness): Client
    {
        $client = $harness->server->clientResolver()->resolve(
            $this->registerDynamic($harness, ['token_endpoint_auth_method' => 'none']),
        );
        $this->assertNotNull($client);

        return $client;
    }

    /**
     * The href of the page's only link.
     */
    private function continueLink(string $html): string
    {
        $this->assertSame(1, preg_match_all('/<a href="([^"]*)"/', $html, $matches), $html);

        return html_entity_decode($matches[1][0], ENT_QUOTES);
    }
}
