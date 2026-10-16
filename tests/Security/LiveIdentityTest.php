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

    public function testARemovedPersonCannotRefreshButComesBackWhenReactivated(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $tokens = $harness->json($harness->exchange($client, $harness->authorizationCode($client)));
        $refresh = fn() => $harness->server->tokenHandler()->handle($harness->form('https://example.com/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $tokens['refresh_token'],
            'client_id' => $client->clientId,
        ]));

        $harness->users->remove('42');
        $this->assertSame('invalid_grant', $harness->json($refresh())['error']);

        $harness->users->add('42', 'Ada');
        $this->assertArrayHasKey('access_token', $harness->json($refresh()));
    }

    public function testIntrospectionReportsARefreshTokenOfARemovedPersonInactive(): void
    {
        $harness = new ServerHarness(['introspection' => true]);
        $harness->confidentialClient('s', ['clientId' => 'rs', 'allowIntrospection' => true]);
        $client = $harness->publicClient();
        $tokens = $harness->json($harness->exchange($client, $harness->authorizationCode($client)));
        $introspect = fn() => $harness->json($harness->server->introspectHandler()->handle($harness->form(
            'https://example.com/oauth/introspect',
            ['token' => $tokens['refresh_token']],
            ['Authorization' => 'Basic ' . base64_encode('rs:s')],
        )));

        $this->assertTrue($introspect()['active']);
        $harness->users->remove('42');
        $this->assertSame(['active' => false], $introspect());
    }

    public function testRevokingEverythingOfAPersonAlsoRefusesTheAccessToken(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $tokens = $harness->json($harness->exchange($client, $harness->authorizationCode($client)));
        $this->assertSame(200, $harness->bearerStatus(Fixtures::MCP, $tokens['access_token']));

        $harness->server->tokenRevoker()->revokeAllForSubject('42');

        $this->assertSame(401, $harness->bearerStatus(Fixtures::MCP, $tokens['access_token']));
    }
}
