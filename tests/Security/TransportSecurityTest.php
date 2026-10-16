<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Security;

use CakeDC\OAuth\Server\Config\ServerConfig;
use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9700, "TLS Terminating Reverse Proxies" and the MCP rule that authorization endpoints use
 * HTTPS: the issuer and every resource are https (loopback excepted) and are configured, never
 * guessed from forwarded headers.
 */
class TransportSecurityTest extends TestCase
{
    public function testPlainHttpIsRefusedOutsideLoopback(): void
    {
        $base = [
            'issuer' => 'https://example.com',
            'secret' => str_repeat('s', 32),
            'resources' => ['https://example.com/mcp' => ['scopes' => ['a' => 'A']]],
        ];
        foreach (
            [
            ['issuer' => 'http://example.com'],
            ['resources' => ['http://example.com/mcp' => ['scopes' => ['a' => 'A']]]],
            ] as $override
        ) {
            try {
                ServerConfig::fromArray($override + $base);
                $this->fail('Accepted plain http');
            } catch (InvalidArgumentException $e) {
                $this->assertStringContainsString('https', $e->getMessage());
            }
        }
    }

    public function testEndpointsComeFromTheConfiguredIssuer(): void
    {
        $harness = new ServerHarness();
        $request = $harness->request(
            'GET',
            'http://evil.example/.well-known/oauth-authorization-server',
            ['X-Forwarded-Host' => 'evil.example'],
        );

        $metadata = $harness->json($harness->server->metadataHandler()->handle($request));

        $this->assertSame('https://example.com/oauth/token', $metadata['token_endpoint']);
    }
}
