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
            $request = $harness->form('https://example.com/oauth/token', ['grant_type' => 'x']);
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
}
