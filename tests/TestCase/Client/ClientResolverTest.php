<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Client;

use CakeDC\OAuth\Server\Client\ApplicationType;
use CakeDC\OAuth\Server\Client\Cimd\MetadataDocumentFetcher;
use CakeDC\OAuth\Server\Client\ClientResolver;
use CakeDC\OAuth\Server\Client\ClientType;
use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Storage\InMemory\InMemoryStorage;
use CakeDC\OAuth\Server\Test\Support\FakeDns;
use CakeDC\OAuth\Server\Test\Support\FakeTransport;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Testing\FrozenClock;
use PHPUnit\Framework\TestCase;

class ClientResolverTest extends TestCase
{
    private const CLAUDE = 'https://claude.ai/oauth/mcp-oauth-client-metadata';

    private InMemoryStorage $storage;

    private FrozenClock $clock;

    private FakeTransport $transport;

    protected function setUp(): void
    {
        $this->storage = new InMemoryStorage();
        $this->clock = new FrozenClock();
        $this->transport = new FakeTransport();
        $this->transport->serve(self::CLAUDE, [
            'client_id' => self::CLAUDE,
            'client_name' => 'Claude',
            'client_uri' => 'https://claude.ai',
            'redirect_uris' => ['https://claude.ai/api/mcp/auth_callback', 'javascript:alert(1)'],
            'grant_types' => ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:jwt-bearer'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
        ], 'max-age=600');
    }

    private function resolver(bool $cimd = true): ClientResolver
    {
        $fetcher = $cimd ? new MetadataDocumentFetcher(new FakeDns(), $this->transport) : null;

        return new ClientResolver($this->storage, $this->clock, $fetcher, 300, 86400);
    }

    public function testResolvesStoredClients(): void
    {
        $client = Fixtures::client();
        $this->storage->saveClient($client);

        $this->assertSame($client->id, $this->resolver()->resolve($client->clientId)?->id);
        $this->assertNull($this->resolver()->resolve('unknown'));
        $this->assertNull($this->resolver()->resolve(''));
    }

    public function testFetchesAndCachesMetadataDocumentClients(): void
    {
        $client = $this->resolver()->resolve(self::CLAUDE);

        $this->assertNotNull($client);
        $this->assertSame(ClientType::MetadataDocument, $client->type);
        $this->assertSame('Claude', $client->name);
        $this->assertSame(['https://claude.ai/api/mcp/auth_callback'], $client->redirectUris);
        $this->assertTrue($client->isPublic());
        $this->assertTrue($client->allowsGrant('refresh_token'));
        $this->assertSame(ApplicationType::Web, $client->applicationType);
        $this->assertEquals($this->clock->now()->modify('+600 seconds'), $client->metadataExpiresAt);

        $this->resolver()->resolve(self::CLAUDE);
        $this->assertCount(1, $this->transport->requests);
        $this->assertSame($client->id, $this->storage->findClientByClientId(self::CLAUDE)?->id);
    }

    public function testRefetchesAfterExpiryKeepingTheSameClient(): void
    {
        $first = $this->resolver()->resolve(self::CLAUDE);
        $this->clock->advance(601);

        $second = $this->resolver()->resolve(self::CLAUDE);

        $this->assertNotNull($first);
        $this->assertNotNull($second);
        $this->assertCount(2, $this->transport->requests);
        $this->assertSame($first->id, $second->id);
        $this->assertEquals($first->createdAt, $second->createdAt);
    }

    public function testCacheTimeIsClamped(): void
    {
        $this->transport->serve(self::CLAUDE, [
            'client_id' => self::CLAUDE,
            'client_name' => 'Claude',
            'redirect_uris' => ['https://claude.ai/api/mcp/auth_callback'],
        ], 'no-store');

        $client = $this->resolver()->resolve(self::CLAUDE);

        $this->assertEquals($this->clock->now()->modify('+300 seconds'), $client?->metadataExpiresAt);
        $this->assertSame(['authorization_code'], $client?->grantTypes);
    }

    public function testRevokedMetadataDocumentClientsAreNotRefetched(): void
    {
        $client = $this->resolver()->resolve(self::CLAUDE);
        $this->assertNotNull($client);
        $this->storage->saveClient($client->withRevokedAt($this->clock->now()));
        $this->clock->advance(10000);

        $this->assertTrue($this->resolver()->resolve(self::CLAUDE)?->isRevoked());
        $this->assertCount(1, $this->transport->requests);
    }

    public function testMetadataDocumentsAreIgnoredWhenDisabled(): void
    {
        $this->assertNull($this->resolver(false)->resolve(self::CLAUDE));
    }

    public function testADocumentWithoutUsableRedirectUrisIsRejected(): void
    {
        $this->transport->serve(self::CLAUDE, [
            'client_id' => self::CLAUDE,
            'client_name' => 'Claude',
            'redirect_uris' => ['javascript:alert(1)'],
        ]);

        $this->expectException(OAuthException::class);
        $this->expectExceptionMessage('no usable redirect_uris');
        $this->resolver()->resolve(self::CLAUDE);
    }

    public function testNativeApplicationsAreDetected(): void
    {
        $url = 'https://claude.ai/oauth/claude-code-client-metadata';
        $this->transport->serve($url, [
            'client_id' => $url,
            'client_name' => 'Claude Code',
            'redirect_uris' => ['http://localhost/callback', 'http://127.0.0.1/callback'],
        ]);

        $this->assertSame(ApplicationType::Native, $this->resolver()->resolve($url)?->applicationType);
    }
}
