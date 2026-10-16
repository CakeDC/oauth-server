<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Security;

use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * RFC 9700, "Access Token Privilege Restriction" and "Misuse of Stolen Access Tokens": audience
 * restriction, live scopes and short lifetimes.
 */
class AccessTokenPrivilegeTest extends TestCase
{
    /**
     * @param list<string> $scopes
     */
    private function call(ServerHarness $harness, string $resource, string $token, array $scopes = []): int
    {
        $next = new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return new Response(200);
            }
        };

        return $harness->server->bearerMiddleware($resource, null, $scopes)
            ->process($harness->request('GET', $resource, ['Authorization' => 'Bearer ' . $token]), $next)
            ->getStatusCode();
    }

    public function testATokenWorksOnlyForItsResource(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $token = $harness->json($harness->exchange($client, $harness->authorizationCode($client)))['access_token'];

        $this->assertSame(200, $this->call($harness, Fixtures::MCP, $token));
        $this->assertSame(401, $this->call($harness, Fixtures::API, $token));
    }

    public function testScopesShrinkAtOnceWhenTheOwnerLosesThem(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $code = $harness->authorizationCode($client, ['scope' => 'content:publish']);
        $token = $harness->json($harness->exchange($client, $code))['access_token'];

        $this->assertSame(200, $this->call($harness, Fixtures::MCP, $token, ['content:publish']));
        $harness->users->scopes['42'] = ['content:read'];
        $this->assertSame(403, $this->call($harness, Fixtures::MCP, $token, ['content:publish']));
    }

    public function testAccessTokensExpireAfterAnHour(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $token = $harness->json($harness->exchange($client, $harness->authorizationCode($client)))['access_token'];

        $harness->clock->advance(3600);

        $this->assertSame(401, $this->call($harness, Fixtures::MCP, $token));
    }

    public function testARevokedClientLosesItsTokensAndCannotAuthenticate(): void
    {
        $harness = new ServerHarness();
        $client = $harness->confidentialClient('s');
        $basic = ['Authorization' => 'Basic ' . base64_encode($client->clientId . ':s')];
        $tokens = $harness->json($harness->exchange($client, $harness->authorizationCode($client), [], $basic));
        $this->assertSame(200, $this->call($harness, Fixtures::MCP, $tokens['access_token']));

        $harness->storage->saveClient($client->withRevokedAt($harness->clock->now()));

        $this->assertSame(401, $this->call($harness, Fixtures::MCP, $tokens['access_token']));
        $response = $harness->server->tokenHandler()->handle($harness->form('https://example.com/oauth/token', [
            'grant_type' => 'client_credentials',
        ], $basic));
        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame('invalid_client', $harness->json($response)['error']);
    }
}
