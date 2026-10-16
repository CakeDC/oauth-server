<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Http\Handler;

use CakeDC\OAuth\Server\AuthorizationServer;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

class IntrospectHandlerTest extends TestCase
{
    private ServerHarness $harness;

    protected function setUp(): void
    {
        $this->harness = new ServerHarness();
        $this->harness->confidentialClient('rs-secret', ['clientId' => 'resource-server', 'allowIntrospection' => true]);
        $this->harness->confidentialClient('other-secret', ['clientId' => 'nosy']);
    }

    private function introspect(string $token, string $credentials = 'resource-server:rs-secret'): ResponseInterface
    {
        return $this->harness->server->introspectHandler()->handle($this->harness->form(
            'https://example.com/oauth/introspect',
            ['token' => $token],
            ['Authorization' => 'Basic ' . base64_encode($credentials)],
        ));
    }

    public function testDescribesLiveAccessTokens(): void
    {
        $client = $this->harness->publicClient();
        $pair = $this->harness->json($this->harness->exchange($client, $this->harness->authorizationCode($client)));

        $body = $this->harness->json($this->introspect($pair['access_token']));

        $this->assertTrue($body['active']);
        $this->assertSame('content:write content:read', $body['scope']);
        $this->assertSame($client->clientId, $body['client_id']);
        $this->assertSame('42', $body['sub']);
        $this->assertSame('Ada', $body['username']);
        $this->assertSame(Fixtures::MCP, $body['aud']);
        $this->assertSame('Bearer', $body['token_type']);
        $this->assertSame($this->harness->clock->now()->getTimestamp() + 3600, $body['exp']);

        $refresh = $this->harness->json($this->introspect($pair['refresh_token']));
        $this->assertTrue($refresh['active']);
        $this->assertSame('refresh_token', $refresh['token_type']);
    }

    public function testDeadTokensAreInactive(): void
    {
        $client = $this->harness->publicClient();
        $pair = $this->harness->json($this->harness->exchange($client, $this->harness->authorizationCode($client)));
        $stored = $this->harness->storage->findTokenByHash(TokenGenerator::hash($pair['access_token']));
        $this->harness->storage->revokeToken((string)$stored?->id, $this->harness->clock->now());

        $this->assertSame(['active' => false], $this->harness->json($this->introspect($pair['access_token'])));
        $this->assertSame(['active' => false], $this->harness->json($this->introspect('unknown')));
    }

    public function testOnlyAllowedConfidentialClientsMayIntrospect(): void
    {
        $this->assertSame(401, $this->introspect('x', 'nosy:other-secret')->getStatusCode());
        $public = $this->harness->publicClient();
        $response = $this->harness->server->introspectHandler()->handle(
            $this->harness->form('https://example.com/oauth/introspect', ['token' => 'x', 'client_id' => $public->clientId]),
        );
        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame('invalid_request', $this->harness->json($this->introspect(''))['error']);
    }

    public function testARepeatedTokenParameterIsRefused(): void
    {
        $response = $this->harness->server->introspectHandler()->handle($this->harness->request(
            'POST',
            'https://example.com/oauth/introspect',
            ['Content-Type' => 'application/x-www-form-urlencoded', 'Authorization' => 'Basic ' . base64_encode('resource-server:rs-secret')],
            'token=a&token=b',
        ));

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('invalid_request', $this->harness->json($response)['error']);
    }

    public function testCanBeDisabled(): void
    {
        $harness = new ServerHarness(['introspection' => false]);

        $response = $harness->server->introspectHandler()->handle($harness->form('https://example.com/oauth/introspect', ['token' => 'x']));

        $this->assertSame(403, $response->getStatusCode());
    }

    public function testExpiredAccessTokensAreInactive(): void
    {
        $client = $this->harness->publicClient();
        $pair = $this->harness->json($this->harness->exchange($client, $this->harness->authorizationCode($client)));
        $this->harness->clock->advance(3601);

        $this->assertSame(['active' => false], $this->harness->json($this->introspect($pair['access_token'])));
    }

    public function testRotatedRefreshTokensAreInactive(): void
    {
        $client = $this->harness->publicClient();
        $pair = $this->harness->json($this->harness->exchange($client, $this->harness->authorizationCode($client)));
        $this->refresh($client->clientId, $pair['refresh_token']);

        $this->assertSame(['active' => false], $this->harness->json($this->introspect($pair['refresh_token'])));
    }

    public function testRefreshTokensOfRevokedClientsAreInactive(): void
    {
        $client = $this->harness->publicClient();
        $pair = $this->harness->json($this->harness->exchange($client, $this->harness->authorizationCode($client)));
        $this->harness->storage->saveClient($client->withRevokedAt($this->harness->clock->now()));

        $this->assertSame(['active' => false], $this->harness->json($this->introspect($pair['refresh_token'])));
    }

    public function testRefreshTokenResponseOmitsNullFields(): void
    {
        $client = $this->harness->publicClient();
        $pair = $this->harness->json($this->harness->exchange($client, $this->harness->authorizationCode($client)));

        $body = $this->harness->json($this->introspect($pair['refresh_token']));

        $this->assertNotContains(null, $body, '', false, true);
        $this->assertArrayHasKey('exp', $body);
    }

    /**
     * A refresh keeps the grant on the new refresh token, so the stored scopes of a refresh token can be
     * wider than what the person may hold today. Introspection reports what an access token refreshed from
     * it would hold today, never the stored grant, so a resource server that wrongly checks only `active`
     * and `scope` cannot be handed more than the person has.
     */
    public function testARefreshTokenIntrospectsWithTheScopesOfToday(): void
    {
        $client = $this->harness->publicClient();
        $pair = $this->harness->json($this->harness->exchange($client, $this->harness->authorizationCode($client)));
        $this->harness->users->scopes['42'] = ['content:read'];

        $this->assertSame('content:read', $this->harness->json($this->introspect($pair['refresh_token']))['scope']);
        $rotated = $this->harness->json($this->refresh($client->clientId, $pair['refresh_token']));
        $access = $this->harness->json($this->introspect($rotated['access_token']));
        $refresh = $this->harness->json($this->introspect($rotated['refresh_token']));

        $this->assertSame('content:read', $access['scope']);
        $this->assertTrue($refresh['active']);
        $this->assertSame('content:read', $refresh['scope']);
        $this->assertSame('refresh_token', $refresh['token_type']);

        // Promoted again: the grant was kept, and it shows the way an access token would.
        $this->harness->users->scopes['42'] = null;
        $this->assertSame(
            'content:write content:read',
            $this->harness->json($this->introspect($rotated['refresh_token']))['scope'],
        );
    }

    public function testARefreshTokenThatNoLongerGrantsAnyScopeIsInactive(): void
    {
        $client = $this->harness->publicClient();
        $pair = $this->harness->json($this->harness->exchange($client, $this->harness->authorizationCode($client)));

        $this->harness->users->scopes['42'] = [];
        $this->assertSame(['active' => false], $this->harness->json($this->introspect($pair['refresh_token'])));
        $this->assertSame(400, $this->refresh($client->clientId, $pair['refresh_token'])->getStatusCode());
    }

    public function testARefreshTokenOfANarrowedClientIsInactiveWhenNothingIsLeft(): void
    {
        $client = $this->harness->publicClient();
        $pair = $this->harness->json($this->harness->exchange($client, $this->harness->authorizationCode($client)));
        $this->harness->storage->saveClient(Fixtures::client([
            'id' => $client->id,
            'clientId' => $client->clientId,
            'scopes' => [],
        ]));

        $this->assertSame(['active' => false], $this->harness->json($this->introspect($pair['refresh_token'])));
        $this->assertSame(400, $this->refresh($client->clientId, $pair['refresh_token'])->getStatusCode());
    }

    public function testARefreshTokenForAResourceNoLongerDeclaredIsInactive(): void
    {
        $client = $this->harness->publicClient();
        $pair = $this->harness->json($this->harness->exchange($client, $this->harness->authorizationCode($client)));
        $settings = Fixtures::resourceSettings();
        unset($settings[Fixtures::MCP]);
        $without = new AuthorizationServer(
            Fixtures::config(['resources' => $settings]),
            $this->harness->storage,
            $this->harness->users,
            $this->harness->userContext,
            $this->harness->factory,
            $this->harness->factory,
            clock: $this->harness->clock,
        );

        $response = $without->introspectHandler()->handle($this->harness->form(
            'https://example.com/oauth/introspect',
            ['token' => $pair['refresh_token']],
            ['Authorization' => 'Basic ' . base64_encode('resource-server:rs-secret')],
        ));

        $this->assertSame(['active' => false], $this->harness->json($response));
        $this->assertTrue($this->harness->json($this->introspect($pair['refresh_token']))['active']);
    }

    public function testPersonalTokens(): void
    {
        $ada = $this->harness->users->users['42'];
        $issued = $this->harness->server->connectionService()
            ->createPersonalToken($ada, 'CI', Fixtures::MCP, ['content:read'], 7);

        $body = $this->harness->json($this->introspect($issued['value']));

        $this->assertTrue($body['active']);
        $this->assertSame('42', $body['sub']);
        $this->assertSame('Ada', $body['username']);
        $this->assertSame('content:read', $body['scope']);
        $this->assertArrayNotHasKey('client_id', $body);
    }

    public function testClientCredentialsTokens(): void
    {
        $this->harness->confidentialClient('s3cret', ['clientId' => 'reports', 'scopes' => ['api']]);
        $this->harness->users->clientIdentity = new ResourceOwner('reports', 'Reporting job', null, SubjectType::Client);
        $issued = $this->harness->json($this->harness->server->tokenHandler()->handle($this->harness->form(
            'https://example.com/oauth/token',
            ['grant_type' => 'client_credentials', 'resource' => Fixtures::API],
            ['Authorization' => 'Basic ' . base64_encode('reports:s3cret')],
        )));

        $body = $this->harness->json($this->introspect($issued['access_token']));

        $this->assertTrue($body['active']);
        $this->assertSame('reports', $body['sub']);
        $this->assertSame('reports', $body['client_id']);
        $this->assertSame(Fixtures::API, $body['aud']);
    }

    public function testIntrospectionIsNotTokenUseAndDoesNotTripReuseDetection(): void
    {
        $client = $this->harness->publicClient();
        $pair = $this->harness->json($this->harness->exchange($client, $this->harness->authorizationCode($client)));
        $rotated = $this->harness->json($this->refresh($client->clientId, $pair['refresh_token']));

        $this->assertTrue($this->harness->json($this->introspect($rotated['access_token']))['active']);
        $this->harness->clock->advance(5);
        $replay = $this->refresh($client->clientId, $pair['refresh_token']);

        $this->assertSame(200, $replay->getStatusCode());
        $stored = $this->harness->storage->findTokenByHash(TokenGenerator::hash($rotated['access_token']));
        $this->assertNull($stored?->lastUsedAt);
        $this->assertTrue($this->harness->json($this->introspect($pair['refresh_token']))['active'] === false);
    }

    private function refresh(string $clientId, string $refreshToken): ResponseInterface
    {
        return $this->harness->server->tokenHandler()->handle($this->harness->form(
            'https://example.com/oauth/token',
            ['grant_type' => 'refresh_token', 'refresh_token' => $refreshToken, 'client_id' => $clientId],
        ));
    }

    /**
     * A resource server that introspects on every request has its own budget (`rateLimit.introspect`,
     * 600 a minute by default): it neither eats the token endpoint's budget nor is blocked by it.
     */
    public function testIntrospectionHasItsOwnRateLimitCounter(): void
    {
        $this->harness = new ServerHarness(['rateLimit' => ['token' => [2, 60], 'introspect' => [3, 60]]]);
        $this->harness->confidentialClient('rs-secret', ['clientId' => 'resource-server', 'allowIntrospection' => true]);
        $token = fn(): ResponseInterface => $this->harness->server->tokenHandler()->handle(
            $this->harness->form('https://example.com/oauth/token', ['grant_type' => 'password']),
        );

        $this->assertSame(400, $token()->getStatusCode());
        $this->assertSame(400, $token()->getStatusCode());
        $this->assertSame(429, $token()->getStatusCode());
        for ($i = 0; $i < 3; $i++) {
            $this->assertSame(200, $this->introspect('unknown')->getStatusCode(), 'introspection ' . $i);
        }
        $this->assertSame(429, $this->introspect('unknown')->getStatusCode());
        $this->harness->clock->advance(60);
        for ($i = 0; $i < 3; $i++) {
            $this->assertSame(200, $this->introspect('unknown')->getStatusCode());
        }
        $this->assertSame(400, $token()->getStatusCode());
    }

    public function testTheDefaultIntrospectionBudgetIsLargerThanTheTokenOne(): void
    {
        $this->harness = new ServerHarness(['rateLimit' => ['token' => [1, 60]]]);
        $this->harness->confidentialClient('rs-secret', ['clientId' => 'resource-server', 'allowIntrospection' => true]);

        for ($i = 0; $i < 20; $i++) {
            $this->assertSame(200, $this->introspect('unknown')->getStatusCode());
        }
    }
}
