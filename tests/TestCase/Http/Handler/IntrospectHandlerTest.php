<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Http\Handler;

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

    public function testCanBeDisabled(): void
    {
        $harness = new ServerHarness(['introspection' => false]);

        $response = $harness->server->introspectHandler()->handle($harness->form('https://example.com/oauth/introspect', ['token' => 'x']));

        $this->assertSame(403, $response->getStatusCode());
    }
}
