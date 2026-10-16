<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Security;

use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use CakeDC\OAuth\Server\Token\ValidationFailure;
use PHPUnit\Framework\TestCase;

/**
 * Tokens follow the person: deactivation and a forced sign-out apply at the next request.
 */
class LiveIdentityTest extends TestCase
{
    public function testDeactivatedPeopleLoseAccessAtOnce(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $tokens = $harness->json($harness->exchange($client, $harness->authorizationCode($client)));

        $harness->users->remove('42');

        $validated = $harness->server->tokenValidator()->validate($tokens['access_token'], Fixtures::MCP);
        $this->assertInstanceOf(ValidationFailure::class, $validated);
    }

    public function testRevokingEverythingOfAPersonIncludesRefreshTokens(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $tokens = $harness->json($harness->exchange($client, $harness->authorizationCode($client)));

        $harness->server->tokenRevoker()->revokeAllForSubject('42');

        $response = $harness->server->tokenHandler()->handle($harness->form('https://example.com/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $tokens['refresh_token'],
            'client_id' => $client->clientId,
        ]));
        $this->assertSame('invalid_grant', $harness->json($response)['error']);
    }
}
