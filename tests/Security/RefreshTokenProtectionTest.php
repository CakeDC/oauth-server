<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Security;

use CakeDC\OAuth\Server\Event\RefreshTokenReused;
use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9700, "Refresh Token Protection": rotation, reuse detection that revokes the family, and
 * binding to the client.
 */
class RefreshTokenProtectionTest extends TestCase
{
    public function testAReplayedRefreshTokenKillsTheWholeFamily(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $first = $harness->json($harness->exchange($client, $harness->authorizationCode($client)));
        $refresh = fn(string $token, string $clientId) => $harness->json($harness->server->tokenHandler()->handle(
            $harness->form('https://example.com/oauth/token', [
                'grant_type' => 'refresh_token',
                'refresh_token' => $token,
                'client_id' => $clientId,
            ]),
        ));

        $second = $refresh($first['refresh_token'], $client->clientId);
        $this->assertArrayHasKey('access_token', $second);
        $harness->clock->advance(31);

        $this->assertSame('invalid_grant', $refresh($first['refresh_token'], $client->clientId)['error']);
        $this->assertSame('invalid_grant', $refresh($second['refresh_token'], $client->clientId)['error']);
        $this->assertCount(1, $harness->events->ofType(RefreshTokenReused::class));
    }

    public function testRefreshTokensAreBoundToTheirClient(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $other = $harness->publicClient();
        $tokens = $harness->json($harness->exchange($client, $harness->authorizationCode($client)));

        $response = $harness->server->tokenHandler()->handle($harness->form('https://example.com/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $tokens['refresh_token'],
            'client_id' => $other->clientId,
        ]));

        $this->assertSame('invalid_grant', $harness->json($response)['error']);
    }
}
