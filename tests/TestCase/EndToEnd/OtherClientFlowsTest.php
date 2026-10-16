<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\EndToEnd;

use CakeDC\OAuth\Server\Grant\Pkce;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class OtherClientFlowsTest extends TestCase
{
    private function ok(): RequestHandlerInterface
    {
        return new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return new Response(200);
            }
        };
    }

    public function testDynamicRegistrationThenIntrospectionByAnotherService(): void
    {
        $harness = new ServerHarness();
        $harness->confidentialClient('rs', ['clientId' => 'api-gateway', 'allowIntrospection' => true]);
        $registered = $harness->json($harness->server->registerHandler()->handle($harness->request(
            'POST',
            'https://example.com/oauth/register',
            ['Content-Type' => 'application/json'],
            (string)json_encode([
                'client_name' => 'Cursor',
                'application_type' => 'native',
                'redirect_uris' => ['cursor://anysphere.cursor/oauth'],
                'token_endpoint_auth_method' => 'none',
            ]),
        )));
        $client = $harness->storage->findClientByClientId($registered['client_id']);
        $this->assertNotNull($client);

        $code = $harness->authorizationCode($client, ['resource' => Fixtures::API, 'scope' => 'api']);
        $tokens = $harness->json($harness->exchange($client, $code));

        $introspection = $harness->json($harness->server->introspectHandler()->handle($harness->form(
            'https://example.com/oauth/introspect',
            ['token' => $tokens['access_token']],
            ['Authorization' => 'Basic ' . base64_encode('api-gateway:rs')],
        )));
        $this->assertTrue($introspection['active']);
        $this->assertSame(Fixtures::API, $introspection['aud']);
    }

    public function testClaudeCodeWithALoopbackCallbackOnARandomPort(): void
    {
        $harness = new ServerHarness();
        $clientId = 'https://claude.ai/oauth/claude-code-client-metadata';
        $harness->transport->serve($clientId, [
            'client_id' => $clientId,
            'client_name' => 'Claude Code',
            'redirect_uris' => ['http://localhost/callback', 'http://127.0.0.1/callback'],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'token_endpoint_auth_method' => 'none',
        ]);
        $harness->signIn();
        $callback = 'http://localhost:51234/callback';
        $url = 'https://example.com/oauth/authorize?' . http_build_query([
            'response_type' => 'code',
            'client_id' => $clientId,
            'redirect_uri' => $callback,
            'state' => 's',
            'code_challenge' => Pkce::challengeFor(ServerHarness::VERIFIER),
            'code_challenge_method' => 'S256',
        ], '', '&', PHP_QUERY_RFC3986);

        $page = (string)$harness->server->authorizeHandler()->handle($harness->request('GET', $url))->getBody();
        $this->assertStringContainsString('your own computer', $page);
        $decision = $harness->server->authorizeHandler()->handle($harness->form(
            'https://example.com/oauth/authorize',
            ServerHarness::formFields($page) + ['decision' => 'approve'],
        ));
        $this->assertStringStartsWith($callback . '?', $decision->getHeaderLine('Location'));

        $response = $harness->server->tokenHandler()->handle($harness->form('https://example.com/oauth/token', [
            'grant_type' => 'authorization_code',
            'code' => ServerHarness::redirectParams($decision)['code'],
            'redirect_uri' => $callback,
            'code_verifier' => ServerHarness::VERIFIER,
            'client_id' => $clientId,
        ]));
        $this->assertSame(200, $response->getStatusCode());
    }

    public function testClientCredentialsForAnAutomation(): void
    {
        $harness = new ServerHarness();
        $harness->confidentialClient('job-secret', ['clientId' => 'nightly-report', 'scopes' => ['content:read']]);
        $harness->users->clientIdentity = new ResourceOwner(
            'nightly-report',
            'Nightly report',
            null,
            SubjectType::Client,
        );

        $tokens = $harness->json($harness->server->tokenHandler()->handle($harness->form(
            'https://example.com/oauth/token',
            ['grant_type' => 'client_credentials'],
            ['Authorization' => 'Basic ' . base64_encode('nightly-report:job-secret')],
        )));

        $response = $harness->server->bearerMiddleware(Fixtures::MCP, null, ['content:read'])->process(
            $harness->request('GET', Fixtures::MCP, ['Authorization' => 'Bearer ' . $tokens['access_token']]),
            $this->ok(),
        );
        $this->assertSame(200, $response->getStatusCode());
    }

    public function testPersonalTokenFromTheConnectionsPage(): void
    {
        $harness = new ServerHarness();
        $harness->signIn();
        $page = $harness->server->connectionsHandler()->handle($harness->form('https://example.com/oauth/connections', [
            'action' => 'create_token',
            'name' => 'CI',
            'resource' => Fixtures::MCP,
            'scope:content:read' => '1',
            'days' => '7',
            'form_token' => $harness->server->formToken()->issue('connections', '42'),
        ]));
        preg_match('/<code>([^<]+)<\/code>/', (string)$page->getBody(), $matches);
        $this->assertArrayHasKey(1, $matches);

        $response = $harness->server->bearerMiddleware(Fixtures::MCP)->process(
            $harness->request('GET', Fixtures::MCP, ['Authorization' => 'Bearer ' . $matches[1]]),
            $this->ok(),
        );
        $this->assertSame(200, $response->getStatusCode());
    }
}
