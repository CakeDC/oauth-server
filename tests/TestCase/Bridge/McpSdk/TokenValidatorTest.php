<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Bridge\McpSdk;

use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use InvalidArgumentException;
use Mcp\Server\Transport\Http\Middleware\AuthorizationMiddleware;
use Mcp\Server\Transport\Http\OAuth\ProtectedResourceMetadata;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class TokenValidatorTest extends TestCase
{
    public function testAllowsValidTokensWithTheirClaims(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $pair = $harness->json($harness->exchange($client, $harness->authorizationCode($client)));

        $result = $harness->server->mcpTokenValidator(Fixtures::MCP)->validate($pair['access_token']);

        $this->assertTrue($result->isAllowed());
        $token = $result->getAccessToken();
        $this->assertNotNull($token);
        $this->assertSame('42', $token->getSubject());
        $this->assertSame($client->clientId, $token->getClientId());
        $this->assertTrue($token->hasScope('content:read'));
        $this->assertSame(Fixtures::MCP, $token->getClaim('aud'));
        $this->assertSame('Ada', $token->getClaim('name'));
    }

    public function testClaimsAreExactAndDoNotLeakTheToken(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $pair = $harness->json($harness->exchange($client, $harness->authorizationCode($client)));

        $token = $harness->server->mcpTokenValidator(Fixtures::MCP)->validate($pair['access_token'])->getAccessToken();

        $this->assertNotNull($token);
        $claims = $token->getClaims();
        $keys = array_keys($claims);
        sort($keys);
        $this->assertSame(['aud', 'client_id', 'exp', 'iat', 'name', 'sub', 'subject_type'], $keys);
        $this->assertIsInt($claims['exp']);
        $this->assertIsInt($claims['iat']);
        $this->assertSame('user', $claims['subject_type']);
        $dump = json_encode($claims, JSON_THROW_ON_ERROR);
        $this->assertStringNotContainsString($pair['access_token'], $dump);
        $this->assertStringNotContainsString(hash('sha256', $pair['access_token']), $dump);
    }

    public function testRejectsInvalidTokens(): void
    {
        $harness = new ServerHarness();

        $result = $harness->server->mcpTokenValidator(Fixtures::MCP)->validate('oauth_at_nonsense');

        $this->assertFalse($result->isAllowed());
        $this->assertSame(401, $result->getStatusCode());
        $this->assertSame('invalid_token', $result->getError());
    }

    public function testRejectsRefreshTokens(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $pair = $harness->json($harness->exchange($client, $harness->authorizationCode($client, ['scope' => 'content:publish'])));

        $result = $harness->server->mcpTokenValidator(Fixtures::MCP)->validate($pair['refresh_token']);

        $this->assertFalse($result->isAllowed());
        $this->assertNull($result->getAccessToken());
        $this->assertSame(401, $result->getStatusCode());
        $this->assertSame('invalid_token', $result->getError());
        $this->assertSame('The access token is invalid.', $result->getErrorDescription());
    }

    public function testAnUndeclaredResourceFailsWhenBuilt(): void
    {
        $this->expectException(InvalidArgumentException::class);

        (new ServerHarness())->server->mcpTokenValidator('https://example.com/nope');
    }

    public function testWorksInsideTheSdkMiddleware(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $pair = $harness->json($harness->exchange($client, $harness->authorizationCode($client)));
        $middleware = new AuthorizationMiddleware(
            $harness->server->mcpTokenValidator(Fixtures::MCP),
            new ProtectedResourceMetadata(Fixtures::MCP, ['https://example.com']),
            null,
            $harness->factory,
            $harness->factory,
        );
        $handler = new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return new Response(204);
            }
        };
        $authorized = ['Authorization' => 'Bearer ' . $pair['access_token']];

        $ok = $middleware->process($harness->request('POST', Fixtures::MCP, $authorized), $handler);
        $denied = $middleware->process($harness->request('POST', Fixtures::MCP), $handler);

        $this->assertSame(204, $ok->getStatusCode());
        $this->assertSame(401, $denied->getStatusCode());
        $this->assertStringContainsString('oauth-protected-resource/mcp', $denied->getHeaderLine('WWW-Authenticate'));
    }
}
