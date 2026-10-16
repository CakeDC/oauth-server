<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Security;

use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use PHPUnit\Framework\TestCase;

/**
 * Abuse of public endpoints: rate limits and registration control.
 */
class AbuseTest extends TestCase
{
    public function testTheTokenEndpointIsRateLimited(): void
    {
        $harness = new ServerHarness(['rateLimit' => ['token' => [3, 60]]]);
        $statuses = [];
        for ($i = 0; $i < 4; $i++) {
            // The key is the connecting address; a spoofed forwarding header must not buy a fresh bucket.
            $request = $harness->form(
                'https://example.com/oauth/token',
                ['grant_type' => 'x'],
                ['X-Forwarded-For' => '198.51.100.' . $i],
            );
            $statuses[] = $harness->server->tokenHandler()->handle($request)->getStatusCode();
        }

        $this->assertSame([400, 400, 400, 429], $statuses);
    }

    public function testRegistrationCanBeClosed(): void
    {
        $harness = new ServerHarness(['registration' => ['mode' => 'closed']]);

        $response = $harness->server->registerHandler()->handle(
            $harness->request('POST', '/', ['Content-Type' => 'application/json'], '{}'),
        );

        $this->assertSame(403, $response->getStatusCode());
        $metadata = $harness->json($harness->server->metadataHandler()->handle($harness->request('GET', '/')));
        $this->assertArrayNotHasKey('registration_endpoint', $metadata);
    }

    public function testTheAuthorizeEndpointIsRateLimited(): void
    {
        $harness = new ServerHarness(['rateLimit' => ['authorize' => [3, 60]]]);
        $statuses = [];
        for ($i = 0; $i < 4; $i++) {
            $request = $harness->request(
                'GET',
                'https://example.com/oauth/authorize?client_id=nobody',
                ['X-Forwarded-For' => '198.51.100.' . $i],
            );
            $statuses[] = $harness->server->authorizeHandler()->handle($request)->getStatusCode();
        }

        $this->assertSame([400, 400, 400, 429], $statuses);
    }

    public function testTheRegisterEndpointIsRateLimited(): void
    {
        $harness = new ServerHarness(['rateLimit' => ['register' => [2, 60]]]);
        $statuses = [];
        for ($i = 0; $i < 3; $i++) {
            $statuses[] = $harness->server->registerHandler()->handle($harness->request(
                'POST',
                'https://example.com/oauth/register',
                ['Content-Type' => 'application/json', 'X-Forwarded-For' => '198.51.100.' . $i],
                '{"redirect_uris":["https://app.example.com/cb"]}',
            ))->getStatusCode();
        }

        $this->assertSame([201, 201, 429], $statuses);
    }

    public function testTokenModeRegistrationNeedsTheInitialAccessToken(): void
    {
        $harness = new ServerHarness(['registration' => ['mode' => 'token', 'initialAccessToken' => 'let-me-in']]);

        $response = $harness->server->registerHandler()->handle($harness->request(
            'POST',
            'https://example.com/oauth/register',
            ['Content-Type' => 'application/json'],
            '{"redirect_uris":["https://app.example.com/cb"]}',
        ));

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame([], $harness->storage->findClients());

        $wrong = $harness->server->registerHandler()->handle($harness->request(
            'POST',
            'https://example.com/oauth/register',
            ['Content-Type' => 'application/json', 'Authorization' => 'Bearer nope'],
            '{"redirect_uris":["https://app.example.com/cb"]}',
        ));
        $this->assertSame(401, $wrong->getStatusCode());
        $this->assertSame([], $harness->storage->findClients());
    }
}
