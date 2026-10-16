<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Http\Handler;

use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use PHPUnit\Framework\TestCase;

class RevokeHandlerTest extends TestCase
{
    public function testClientsRevokeTheirTokens(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $other = $harness->publicClient();
        $pair = $harness->json($harness->exchange($client, $harness->authorizationCode($client)));
        $revoke = fn(string $token, string $clientId) => $harness->server->revokeHandler()->handle(
            $harness->form('https://example.com/oauth/revoke', ['token' => $token, 'client_id' => $clientId]),
        );

        $foreign = $revoke($pair['refresh_token'], $other->clientId);
        $this->assertSame(200, $foreign->getStatusCode());
        $this->assertNull($harness->storage->findTokenByHash(TokenGenerator::hash($pair['access_token']))?->revokedAt);

        $response = $revoke($pair['refresh_token'], $client->clientId);
        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('{}', (string)$response->getBody());
        $this->assertNotNull($harness->storage->findTokenByHash(TokenGenerator::hash($pair['access_token']))?->revokedAt);

        $this->assertSame(200, $revoke('unknown', $client->clientId)->getStatusCode());
    }

    public function testRequestShape(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $handler = $harness->server->revokeHandler();

        $missing = $handler->handle($harness->form('https://example.com/oauth/revoke', ['client_id' => $client->clientId]));
        $this->assertSame('invalid_request', $harness->json($missing)['error']);
        $unknown = $handler->handle($harness->form('https://example.com/oauth/revoke', ['token' => 'x', 'client_id' => 'nobody']));
        $this->assertSame(401, $unknown->getStatusCode());
        $this->assertSame(204, $handler->handle($harness->request('OPTIONS', '/'))->getStatusCode());
        $this->assertSame(405, $handler->handle($harness->request('GET', '/'))->getStatusCode());
    }
}
