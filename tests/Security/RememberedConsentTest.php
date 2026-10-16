<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Security;

use CakeDC\OAuth\Server\Client\ApplicationType;
use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Grant\Pkce;
use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use PHPUnit\Framework\TestCase;

/**
 * RFC 8252 section 8.6: a remembered consent answers without interaction only when the client's
 * identity is assured (a confidential client, or an https redirect URI that is not loopback). For a
 * public loopback or private-scheme client, whoever opens the authorization URL chooses the port and
 * the PKCE challenge, so the person is always asked.
 */
class RememberedConsentTest extends TestCase
{
    private const CLAUDE_CODE = 'https://claude.ai/oauth/claude-code-client-metadata';

    public function testAnotherLoopbackPortWithAnotherChallengeIsAskedAgain(): void
    {
        $harness = new ServerHarness();
        $client = $this->claudeCode($harness);
        // The person connects Claude Code once (port 51000) and approves.
        $harness->authorizationCode($client, ['redirect_uri' => 'http://127.0.0.1:51000/callback']);
        $codes = $this->codeCount($harness);

        // Later, another program on the machine opens the URL with its own port and verifier.
        $attackerVerifier = str_repeat('A', 43);
        $response = $harness->server->authorizeHandler()->handle($harness->request('GET', $harness->authorizeUrl($client, [
            'redirect_uri' => 'http://127.0.0.1:6666/callback',
            'code_challenge' => Pkce::challengeFor($attackerVerifier),
        ])));
        $html = (string)$response->getBody();

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('', $response->getHeaderLine('Location'));
        $this->assertStringContainsString('consent_token', $html);
        $this->assertStringContainsString('You approved this application before', $html);
        $this->assertStringContainsString('any program on this computer', $html);
        $this->assertSame($codes, $this->codeCount($harness), 'No code without interaction');
    }

    public function testTheSamePortIsAskedAgainToo(): void
    {
        $harness = new ServerHarness();
        $client = $this->claudeCode($harness);
        $harness->authorizationCode($client, ['redirect_uri' => 'http://127.0.0.1:51000/callback']);

        $response = $harness->server->authorizeHandler()->handle($harness->request('GET', $harness->authorizeUrl($client, [
            'redirect_uri' => 'http://127.0.0.1:51000/callback',
        ])));

        $this->assertSame(200, $response->getStatusCode());
        // Approving again still works and issues the code.
        $fields = ServerHarness::formFields((string)$response->getBody()) + ['decision' => 'approve'];
        $approved = $harness->server->authorizeHandler()->handle(
            $harness->form('https://example.com/oauth/authorize', $fields),
        );
        $this->assertSame(303, $approved->getStatusCode());
        $this->assertStringStartsWith('http://127.0.0.1:51000/callback?code=', $approved->getHeaderLine('Location'));
    }

    public function testAnHttpsRedirectIsStillApprovedSilently(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $harness->authorizationCode($client);

        $response = $harness->server->authorizeHandler()->handle(
            $harness->request('GET', $harness->authorizeUrl($client, ['state' => 'again'])),
        );

        $this->assertSame(302, $response->getStatusCode());
        $this->assertArrayHasKey('code', ServerHarness::redirectParams($response));
    }

    public function testAConfidentialLoopbackClientIsStillApprovedSilently(): void
    {
        $harness = new ServerHarness();
        $client = $harness->confidentialClient('cs-secret', [
            'applicationType' => ApplicationType::Native,
            'redirectUris' => ['http://127.0.0.1/callback'],
        ]);
        $harness->authorizationCode($client, ['redirect_uri' => 'http://127.0.0.1:51000/callback']);

        $response = $harness->server->authorizeHandler()->handle($harness->request('GET', $harness->authorizeUrl($client, [
            'redirect_uri' => 'http://127.0.0.1:6666/callback',
        ])));

        $this->assertSame(302, $response->getStatusCode());
        $this->assertStringStartsWith('http://127.0.0.1:6666/callback?code=', $response->getHeaderLine('Location'));
    }

    public function testHttpsLoopbackAndPrivateSchemesAreAskedAgain(): void
    {
        $harness = new ServerHarness();
        $clients = [
            'https loopback' => $harness->publicClient(['redirectUris' => ['https://localhost:8443/cb']]),
            'private scheme' => $harness->publicClient([
                'applicationType' => ApplicationType::Native,
                'redirectUris' => ['com.example.app:/cb'],
            ]),
        ];
        foreach ($clients as $kind => $client) {
            $harness->authorizationCode($client);

            $response = $harness->server->authorizeHandler()->handle(
                $harness->request('GET', $harness->authorizeUrl($client)),
            );

            $this->assertSame(200, $response->getStatusCode(), $kind);
            $this->assertStringContainsString('You approved this application before', (string)$response->getBody(), $kind);
        }
    }

    public function testAFirstConsentDoesNotSayApprovedBefore(): void
    {
        $harness = new ServerHarness();
        $client = $this->claudeCode($harness);
        $harness->signIn();

        $html = (string)$harness->server->authorizeHandler()->handle($harness->request('GET', $harness->authorizeUrl($client, [
            'redirect_uri' => 'http://127.0.0.1:51000/callback',
        ])))->getBody();

        $this->assertStringContainsString('consent_token', $html);
        $this->assertStringNotContainsString('You approved this application before', $html);
    }

    private function codeCount(ServerHarness $harness): int
    {
        /** @var array<string, mixed> $codes */
        $codes = (fn(): array => $this->codes)->call($harness->storage);

        return count($codes);
    }

    private function claudeCode(ServerHarness $harness): Client
    {
        $harness->transport->serve(self::CLAUDE_CODE, [
            'client_id' => self::CLAUDE_CODE,
            'client_name' => 'Claude Code',
            'redirect_uris' => ['http://localhost/callback', 'http://127.0.0.1/callback'],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'token_endpoint_auth_method' => 'none',
        ]);
        $client = $harness->server->clientResolver()->resolve(self::CLAUDE_CODE);
        $this->assertNotNull($client);

        return $client;
    }
}
