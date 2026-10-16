<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Security;

use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9700, "Authorization Code Injection" and "PKCE Downgrade Attack": codes are bound to their
 * client, redirect URI and PKCE challenge; S256 is mandatory; codes are short-lived and single-use.
 */
class AuthorizationCodeInjectionTest extends TestCase
{
    public function testAStolenCodeIsUselessWithoutTheVerifierOrToAnotherClient(): void
    {
        $harness = new ServerHarness();
        $victim = $harness->publicClient();
        $attacker = $harness->publicClient();
        $code = $harness->authorizationCode($victim);

        $this->assertSame('invalid_grant', $harness->json($harness->exchange($attacker, $code))['error']);
        $wrong = $harness->exchange($victim, $code, ['code_verifier' => str_repeat('a', 43)]);
        $this->assertSame('invalid_grant', $harness->json($wrong)['error']);
    }

    public function testPkceCannotBeDowngradedOrSkipped(): void
    {
        $harness = new ServerHarness();
        $client = $harness->registeredClient();
        $harness->signIn();

        $variants = [['code_challenge_method' => 'plain'], ['code_challenge_method' => null], ['code_challenge' => null]];
        foreach ($variants as $params) {
            $url = $harness->authorizeUrl($client, $params);
            $response = $harness->server->authorizeHandler()->handle($harness->request('GET', $url));
            $this->assertSame('invalid_request', ServerHarness::redirectParams($response)['error']);
        }
    }

    public function testConfidentialClientsNeedPkceToo(): void
    {
        $harness = new ServerHarness();
        $client = $harness->confidentialClient();
        $harness->signIn();

        $url = $harness->authorizeUrl($client, ['code_challenge' => null]);
        $response = $harness->server->authorizeHandler()->handle($harness->request('GET', $url));

        $this->assertSame('invalid_request', ServerHarness::redirectParams($response)['error']);
    }

    public function testCodesAreSingleUseAndShortLived(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $code = $harness->authorizationCode($client);
        $first = $harness->json($harness->exchange($client, $code));

        $this->assertSame('invalid_grant', $harness->json($harness->exchange($client, $code))['error']);
        $stored = $harness->storage->findTokenByHash(TokenGenerator::hash($first['refresh_token']));
        $this->assertNotNull($stored?->revokedAt);

        $late = $harness->authorizationCode($client);
        $harness->clock->advance(61);
        $this->assertSame('invalid_grant', $harness->json($harness->exchange($client, $late))['error']);
    }

    public function testADifferentRedirectUriAtTheTokenEndpointIsRefused(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $code = $harness->authorizationCode($client);

        $response = $harness->exchange($client, $code, ['redirect_uri' => 'https://app.example.com/other']);

        $this->assertSame('invalid_grant', $harness->json($response)['error']);
    }

    public function testTheVerifierCannotBeOmitted(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $code = $harness->authorizationCode($client);

        $response = $harness->server->tokenHandler()->handle($harness->form('https://example.com/oauth/token', [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $client->redirectUris[0],
            'client_id' => $client->clientId,
        ]));

        $this->assertSame('invalid_request', $harness->json($response)['error']);
    }

    public function testReusingACodeRevokesTheAccessTokenToo(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $code = $harness->authorizationCode($client);
        $first = $harness->json($harness->exchange($client, $code));
        $this->assertSame(200, $harness->bearerStatus(Fixtures::MCP, $first['access_token']));

        $harness->exchange($client, $code);

        $this->assertSame(401, $harness->bearerStatus(Fixtures::MCP, $first['access_token']));
    }
}
