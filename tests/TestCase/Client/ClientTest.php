<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Client;

use CakeDC\OAuth\Server\Client\ApplicationType;
use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Client\ClientAuthMethod;
use CakeDC\OAuth\Server\Client\ClientType;
use CakeDC\OAuth\Server\Client\GrantType;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

class ClientTest extends TestCase
{
    /**
     * @param list<string> $redirectUris
     */
    private function client(ClientType $type, string $clientId, array $redirectUris): Client
    {
        return new Client(
            id: 'c0a8a1e2-0000-4000-8000-000000000001',
            clientId: $clientId,
            type: $type,
            applicationType: ApplicationType::Web,
            name: 'Claude',
            redirectUris: $redirectUris,
            grantTypes: [GrantType::AUTHORIZATION_CODE, GrantType::REFRESH_TOKEN],
            authMethod: ClientAuthMethod::None,
            createdAt: new DateTimeImmutable('2026-01-01 00:00:00'),
        );
    }

    public function testMetadataDocumentClientsAreNamedByTheirClientIdHost(): void
    {
        $client = $this->client(
            ClientType::MetadataDocument,
            'https://Claude.ai/oauth/mcp-oauth-client-metadata',
            ['https://evil.example/cb'],
        );

        $this->assertSame('claude.ai', $client->displayHost());
    }

    public function testOtherClientsAreNamedByTheirFirstRedirectHost(): void
    {
        $client = $this->client(
            ClientType::Dynamic,
            'abc',
            ['https://app.example.com/cb', 'https://other.example/cb'],
        );

        $this->assertSame('app.example.com', $client->displayHost());
        $this->assertTrue($client->isPublic());
        $this->assertTrue($client->allowsGrant('refresh_token'));
        $this->assertFalse($client->allowsGrant('client_credentials'));
    }

    public function testDetectsLoopbackOnlyClients(): void
    {
        $this->assertTrue($this->client(ClientType::Dynamic, 'a', ['http://127.0.0.1/cb', 'http://localhost/cb'])
            ->redirectsOnlyToLoopback());
        $this->assertFalse($this->client(ClientType::Dynamic, 'a', ['http://127.0.0.1/cb', 'https://x.example/cb'])
            ->redirectsOnlyToLoopback());
    }

    public function testEveryRedirectThatStaysOnThisComputerCounts(): void
    {
        $this->assertTrue($this->client(ClientType::Dynamic, 'a', ['http://127.0.0.1/cb', 'https://127.0.0.5/cb'])
            ->redirectsOnlyToLoopback());
        $this->assertTrue($this->client(ClientType::Dynamic, 'a', ['https://app.localhost/cb'])
            ->redirectsOnlyToLoopback());
        $this->assertTrue($this->client(ClientType::Dynamic, 'a', ['com.example.app:/cb'])
            ->redirectsOnlyToLoopback());
        $this->assertFalse($this->client(ClientType::Dynamic, 'a', ['com.example.app:/cb', 'https://x.example/cb'])
            ->redirectsOnlyToLoopback());
    }

    public function testWithersReturnModifiedCopies(): void
    {
        $client = $this->client(ClientType::Dynamic, 'abc', ['https://app.example.com/cb']);
        $at = new DateTimeImmutable('2026-02-02 00:00:00');

        $revoked = $client->withRevokedAt($at);
        $used = $client->withLastUsedAt($at);

        $this->assertFalse($client->isRevoked());
        $this->assertTrue($revoked->isRevoked());
        $this->assertSame($at, $used->lastUsedAt);
        $this->assertSame('abc', $revoked->clientId);
    }
}
