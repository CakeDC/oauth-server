<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Http\Middleware;

use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use CakeDC\OAuth\Server\Token\ValidatedToken;
use InvalidArgumentException;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class BearerTokenMiddlewareTest extends TestCase
{
    private ServerHarness $harness;

    private RequestHandlerInterface $next;

    public ?ServerRequestInterface $seen = null;

    protected function setUp(): void
    {
        $this->harness = new ServerHarness();
        $test = $this;
        $this->next = new class ($test) implements RequestHandlerInterface {
            public function __construct(private readonly BearerTokenMiddlewareTest $test)
            {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->test->seen = $request;

                return new Response(200);
            }
        };
    }

    private function token(): string
    {
        $client = $this->harness->publicClient();
        $code = $this->harness->authorizationCode($client);

        return $this->harness->json($this->harness->exchange($client, $code))['access_token'];
    }

    /**
     * @param list<string> $requiredScopes
     */
    private function call(?string $authorization, array $requiredScopes = []): ResponseInterface
    {
        $middleware = $this->harness->server->bearerMiddleware(
            Fixtures::MCP,
            'https://example.com/.well-known/oauth-protected-resource/mcp',
            $requiredScopes,
        );
        $headers = $authorization === null ? [] : ['Authorization' => $authorization];

        return $middleware->process($this->harness->request('POST', Fixtures::MCP, $headers), $this->next);
    }

    public function testPassesValidTokensWithTheirOwner(): void
    {
        $response = $this->call('Bearer ' . $this->token(), ['content:read']);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertInstanceOf(ValidatedToken::class, $this->seen?->getAttribute(ValidatedToken::class));
        $this->assertSame('42', $this->seen?->getAttribute(ResourceOwner::class)?->subject);
    }

    public function testRejectsARefreshTokenAsInvalid(): void
    {
        $client = $this->harness->publicClient();
        $code = $this->harness->authorizationCode($client, ['scope' => 'content:publish']);
        $pair = $this->harness->json($this->harness->exchange($client, $code));

        $response = $this->call('Bearer ' . $pair['refresh_token'], ['content:read']);

        $this->assertSame(401, $response->getStatusCode());
        $this->assertNull($this->seen);
        $this->assertSame(
            ['error' => 'invalid_token', 'error_description' => 'The access token is invalid.'],
            $this->harness->json($response),
        );
        $this->assertStringContainsString(
            'error_description="The access token is invalid."',
            $response->getHeaderLine('WWW-Authenticate'),
        );
    }

    public function testChallengesWithoutAToken(): void
    {
        $response = $this->call(null);

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame(
            'Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource/mcp"',
            $response->getHeaderLine('WWW-Authenticate'),
        );
        $this->assertNull($this->seen);
        $this->assertSame('{}', (string)$response->getBody());
    }

    public function testChallengesWithoutATokenNameTheRequiredScopes(): void
    {
        $response = $this->call(null, ['content:read']);

        $this->assertSame(401, $response->getStatusCode());
        $this->assertStringContainsString('scope="content:read"', $response->getHeaderLine('WWW-Authenticate'));
        $this->assertStringNotContainsString('error=', $response->getHeaderLine('WWW-Authenticate'));
    }

    public function testABareSchemeCountsAsNoToken(): void
    {
        $response = $this->call('Bearer');

        $this->assertSame(401, $response->getStatusCode());
        $this->assertStringNotContainsString('error=', $response->getHeaderLine('WWW-Authenticate'));
    }

    public function testRejectsInvalidTokens(): void
    {
        $response = $this->call('Bearer oauth_at_nonsense');

        $this->assertSame(401, $response->getStatusCode());
        $header = $response->getHeaderLine('WWW-Authenticate');
        $this->assertStringContainsString('error="invalid_token"', $header);
        $this->assertStringContainsString('error_description="The access token is invalid."', $header);
    }

    public function testRejectsMalformedHeaders(): void
    {
        $this->assertSame(400, $this->call('Bearer two words')->getStatusCode());
        $this->assertSame(401, $this->call('Basic dXNlcjpwYXNz')->getStatusCode());
    }

    public function testATrailingNewlineIsMalformed(): void
    {
        $response = $this->call("Bearer abc\n");

        $this->assertSame(400, $response->getStatusCode());
        $this->assertNull($this->seen);
    }

    public function testInsufficientScope(): void
    {
        $response = $this->call('Bearer ' . $this->token(), ['content:publish']);

        $this->assertSame(403, $response->getStatusCode());
        $header = $response->getHeaderLine('WWW-Authenticate');
        $this->assertStringContainsString('scope="content:publish"', $header);
        $this->assertStringContainsString('error="insufficient_scope"', $header);
    }

    public function testPreflightsPassThroughWithoutAttributes(): void
    {
        $middleware = $this->harness->server->bearerMiddleware(Fixtures::MCP);
        $request = $this->harness->request('OPTIONS', Fixtures::MCP, ['Access-Control-Request-Method' => 'POST']);

        $response = $middleware->process($request, $this->next);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertNotNull($this->seen);
        $this->assertNull($this->seen->getAttribute(ValidatedToken::class));
        $this->assertNull($this->seen->getAttribute(ResourceOwner::class));
    }

    public function testOtherOptionsRequestsAreChallenged(): void
    {
        $middleware = $this->harness->server->bearerMiddleware(Fixtures::MCP);

        $response = $middleware->process($this->harness->request('OPTIONS', Fixtures::MCP), $this->next);

        $this->assertSame(401, $response->getStatusCode());
        $this->assertNull($this->seen);
    }

    public function testATokenForAnotherResourceIsInvalid(): void
    {
        $middleware = $this->harness->server->bearerMiddleware(Fixtures::API);
        $headers = ['Authorization' => 'Bearer ' . $this->token()];

        $response = $middleware->process($this->harness->request('POST', Fixtures::API, $headers), $this->next);

        $this->assertSame(401, $response->getStatusCode());
        $this->assertStringContainsString('error="invalid_token"', $response->getHeaderLine('WWW-Authenticate'));
    }

    public function testImpliedScopesSatisfyRequirements(): void
    {
        $client = $this->harness->publicClient();
        $code = $this->harness->authorizationCode($client, ['scope' => 'content:publish']);
        $token = $this->harness->json($this->harness->exchange($client, $code))['access_token'];

        $this->assertSame(200, $this->call('Bearer ' . $token, ['content:read'])->getStatusCode());
    }

    public function testTwoAuthorizationHeadersAreMalformed(): void
    {
        $middleware = $this->harness->server->bearerMiddleware(Fixtures::MCP);
        $request = $this->harness->request('POST', Fixtures::MCP)->withHeader('Authorization', ['Bearer a', 'Bearer b']);

        $this->assertSame(400, $middleware->process($request, $this->next)->getStatusCode());
        $this->assertNull($this->seen);
    }

    public function testChallengeValuesAreEscaped(): void
    {
        $middleware = $this->harness->server->bearerMiddleware(Fixtures::MCP, "https://e.com/a\"b\\c\r\nX: y");

        $response = $middleware->process($this->harness->request('POST', Fixtures::MCP), $this->next);

        $this->assertSame(
            'Bearer resource_metadata="https://e.com/a\\"b\\\\cX: y"',
            $response->getHeaderLine('WWW-Authenticate'),
        );
    }

    public function testUndeclaredScopesFailWhenBuilt(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->harness->server->bearerMiddleware(Fixtures::MCP, null, ['content:nope']);
    }

    public function testAnUndeclaredResourceFailsWhenBuilt(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->harness->server->bearerMiddleware('https://example.com/nope');
    }
}
