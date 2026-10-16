<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Client;

use CakeDC\OAuth\Server\Client\ApplicationType;
use CakeDC\OAuth\Server\Client\Cimd\FetchedResponse;
use CakeDC\OAuth\Server\Client\Cimd\MetadataDocumentFetcher;
use CakeDC\OAuth\Server\Client\ClientResolver;
use CakeDC\OAuth\Server\Client\ClientType;
use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\RateLimit\RateLimiter;
use CakeDC\OAuth\Server\Storage\InMemory\InMemoryStorage;
use CakeDC\OAuth\Server\Test\Support\FakeDns;
use CakeDC\OAuth\Server\Test\Support\FakeTransport;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\FlakyClientRepository;
use CakeDC\OAuth\Server\Testing\ArrayCache;
use CakeDC\OAuth\Server\Testing\FrozenClock;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Throwable;

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

    public function testAMetadataDocumentNameWithInvisibleCharactersIsReplacedByTheHost(): void
    {
        foreach (["Claude\u{202E}", "Cla\u{200B}ude", "\u{00A0}", "\u{200B}\u{200D}\u{2060}"] as $i => $name) {
            $url = 'https://claude.ai/metadata' . $i . '.json';
            $this->transport->serve($url, [
                'client_id' => $url,
                'client_name' => $name,
                'redirect_uris' => ['https://claude.ai/cb'],
                'token_endpoint_auth_method' => 'none',
            ], 'max-age=600');

            $client = $this->resolver()->resolve($url);

            $this->assertSame('claude.ai', $client?->name, $name);
        }
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

    public function testPruningKeepsARevokedClientRevoked(): void
    {
        $client = $this->resolver()->resolve(self::CLAUDE);
        $this->assertNotNull($client);
        $this->storage->saveClient($client->withRevokedAt($this->clock->now()));
        $this->clock->advance(8 * 86400);

        $result = $this->storage->prune($this->clock->now(), 7 * 86400, 86400);

        $this->assertSame(0, $result->clients);
        $this->assertTrue($this->resolver()->resolve(self::CLAUDE)?->isRevoked());
        $this->assertCount(1, $this->transport->requests);
    }

    public function testTheHostPolicyAppliesToCachedClients(): void
    {
        $allowed = new MetadataDocumentFetcher(new FakeDns(), $this->transport, allowedHosts: ['claude.ai']);
        $this->assertNotNull((new ClientResolver($this->storage, $this->clock, $allowed))->resolve(self::CLAUDE));
        $restricted = new MetadataDocumentFetcher(new FakeDns(), $this->transport, allowedHosts: ['other.example']);
        $resolver = new ClientResolver($this->storage, $this->clock, $restricted);

        try {
            $resolver->resolve(self::CLAUDE);
            $this->fail('The cached client of a removed host must be refused.');
        } catch (OAuthException $e) {
            $this->assertSame('invalid_client', $e->error);
        }
        $this->assertCount(1, $this->transport->requests);
    }

    public function testTheHostPolicyAppliesToStaleAndRevokedRows(): void
    {
        $client = $this->resolver()->resolve(self::CLAUDE);
        $this->assertNotNull($client);
        $restricted = new MetadataDocumentFetcher(new FakeDns(), $this->transport, allowedHosts: ['other.example']);
        $resolver = new ClientResolver($this->storage, $this->clock, $restricted);
        $this->clock->advance(700);
        $this->storage->saveClient($client->withRevokedAt($this->clock->now()));

        $this->expectException(OAuthException::class);
        $resolver->resolve(self::CLAUDE);
    }

    private function limited(int $max = 2, int $window = 60): ClientResolver
    {
        $cache = new ArrayCache($this->clock);

        return new ClientResolver(
            $this->storage,
            $this->clock,
            new MetadataDocumentFetcher(new FakeDns(), $this->transport),
            300,
            86400,
            true,
            new RateLimiter($cache, $this->clock, ['cimd' => [$max, $window]]),
            $cache,
        );
    }

    private function serveClient(int $i): string
    {
        $id = 'https://client.example/c/' . $i;
        $this->transport->serve($id, [
            'client_id' => $id,
            'client_name' => 'C' . $i,
            'redirect_uris' => ['https://client.example/cb'],
        ]);

        return $id;
    }

    public function testOneRequesterIsCutOffAfterTheFetchBudget(): void
    {
        $resolver = $this->limited(2);
        $resolver->resolve($this->serveClient(1), '203.0.113.1');
        $resolver->resolve($this->serveClient(2), '203.0.113.1');

        try {
            $resolver->resolve($this->serveClient(3), '203.0.113.1');
            $this->fail('The third fetch of one requester must be refused.');
        } catch (OAuthException $e) {
            $this->assertSame(429, $e->status);
            $this->assertArrayHasKey('Retry-After', $e->headers);
        }
        $this->assertCount(2, $this->transport->requests);
        $this->assertNull($this->storage->findClientByClientId('https://client.example/c/3'));
    }

    public function testASecondRequesterStillWorks(): void
    {
        $resolver = $this->limited(1);
        $resolver->resolve($this->serveClient(1), '203.0.113.1');

        $this->assertNotNull($resolver->resolve($this->serveClient(2), '203.0.113.2'));
    }

    public function testCachedClientsAreNotCounted(): void
    {
        $resolver = $this->limited(1);
        for ($i = 0; $i < 5; $i++) {
            $this->assertNotNull($resolver->resolve(self::CLAUDE, '203.0.113.1'));
        }
        $this->assertCount(1, $this->transport->requests);
        // The budget still has room for no more than the one fetch it counted.
        $this->expectException(OAuthException::class);
        $resolver->resolve($this->serveClient(1), '203.0.113.1');
    }

    public function testAnExpiredCacheEntryCountsAsAFetch(): void
    {
        $resolver = $this->limited(1, 86400);
        $resolver->resolve(self::CLAUDE, '203.0.113.1');
        $this->clock->advance(601);

        try {
            $resolver->resolve(self::CLAUDE, '203.0.113.1');
            $this->fail('The refetch must count against the budget.');
        } catch (OAuthException $e) {
            $this->assertSame(429, $e->status);
        }
    }

    public function testWithoutARequesterNothingIsCounted(): void
    {
        $resolver = $this->limited(1);
        $resolver->resolve($this->serveClient(1));
        $resolver->resolve($this->serveClient(2));

        $this->assertCount(2, $this->transport->requests);
    }

    public function testADefiniteRejectionIsRememberedAndNotRefetched(): void
    {
        $resolver = $this->limited(5);
        $this->transport->responses[self::CLAUDE] = new FetchedResponse(404, [], '');

        for ($i = 0; $i < 3; $i++) {
            try {
                $resolver->resolve(self::CLAUDE, '203.0.113.1');
                $this->fail('Resolved a rejected client.');
            } catch (OAuthException $e) {
                $this->assertSame('invalid_client', $e->error);
            }
        }
        $this->assertCount(1, $this->transport->requests);

        $this->clock->advance(61);
        $this->transport->serve(self::CLAUDE, [
            'client_id' => self::CLAUDE,
            'client_name' => 'Claude',
            'redirect_uris' => ['https://claude.ai/cb'],
        ]);
        $this->assertNotNull($resolver->resolve(self::CLAUDE, '203.0.113.1'));
        $this->assertCount(2, $this->transport->requests);
    }

    /**
     * CIMD: "The authorization server MUST NOT cache error responses." A first fetch that fails for a
     * temporary reason is not remembered, so the client works as soon as its host answers again.
     */
    #[DataProvider('temporaryFailures')]
    public function testATemporaryFailureOfAFirstFetchIsNotRemembered(Throwable|FetchedResponse $failure): void
    {
        $resolver = $this->limited(5);
        $good = $this->transport->responses[self::CLAUDE];
        $this->transport->responses[self::CLAUDE] = $failure;

        for ($i = 0; $i < 2; $i++) {
            try {
                $resolver->resolve(self::CLAUDE);
                $this->fail('Resolved an unreachable client.');
            } catch (OAuthException $e) {
                $this->assertTrue($e->temporary);
                $this->assertSame('invalid_client', $e->error);
            }
        }
        $this->assertCount(2, $this->transport->requests);

        $this->transport->responses[self::CLAUDE] = $good;
        $this->assertNotNull($resolver->resolve(self::CLAUDE));
        $this->assertCount(3, $this->transport->requests);
    }

    /**
     * A DNS failure (resolver timeout, SERVFAIL) is temporary too: it is not remembered as a rejection,
     * and the next request looks the host up again.
     */
    public function testAFailedDnsLookupIsNotRememberedAsARejection(): void
    {
        $dns = new FakeDns();
        $dns->failing = ['claude.ai'];
        $resolver = new ClientResolver(
            $this->storage,
            $this->clock,
            new MetadataDocumentFetcher($dns, $this->transport),
            300,
            86400,
            false,
            null,
            new ArrayCache($this->clock),
        );

        for ($i = 0; $i < 2; $i++) {
            try {
                $resolver->resolve(self::CLAUDE, '203.0.113.1');
                $this->fail('Resolved a client whose host could not be looked up.');
            } catch (OAuthException $e) {
                $this->assertTrue($e->temporary);
            }
        }
        $this->assertSame(['claude.ai', 'claude.ai'], $dns->lookups);

        $dns->failing = [];
        $this->assertNotNull($resolver->resolve(self::CLAUDE, '203.0.113.1'));
    }

    /**
     * A failure remembered by an older version, whose description had double quotes, is ignored instead
     * of turning into an InvalidArgumentException: the document is fetched again.
     */
    public function testARememberedFailureWithAnOldDescriptionIsIgnored(): void
    {
        $cache = new ArrayCache($this->clock);
        $cache->set(
            'oauth_cf_' . substr(hash('sha256', self::CLAUDE), 0, 40),
            ['message' => 'Only public clients (token_endpoint_auth_method "none") are supported.', 'temporary' => false],
            60,
        );
        $resolver = new ClientResolver(
            $this->storage,
            $this->clock,
            new MetadataDocumentFetcher(new FakeDns(), $this->transport),
            300,
            86400,
            false,
            null,
            $cache,
        );

        $this->assertNotNull($resolver->resolve(self::CLAUDE));
        $this->assertCount(1, $this->transport->requests);
    }

    /**
     * A client_id is at most 2048 characters (the storage indexes a hash of it, and nothing longer is
     * looked up or fetched).
     */
    public function testAClientIdLongerThan2048CharactersIsUnknown(): void
    {
        $long = Fixtures::client(['clientId' => str_repeat('a', 2049)]);
        $limit = Fixtures::client(['clientId' => str_repeat('b', 2048)]);
        $this->storage->saveClient($long);
        $this->storage->saveClient($limit);

        $this->assertNull($this->resolver()->resolve($long->clientId));
        $this->assertSame($limit->id, $this->resolver()->resolve($limit->clientId)?->id);
        $document = 'https://claude.ai/' . str_repeat('x', 2049 - strlen('https://claude.ai/'));
        $this->assertNull($this->resolver()->resolve($document));
        $this->assertSame([], $this->transport->requests);
    }

    /**
     * @return array<string, array{\CakeDC\OAuth\Server\Client\Cimd\FetchedResponse}>
     */
    public static function definiteRejections(): array
    {
        return [
            'http 404' => [new FetchedResponse(404, [], '')],
            'not json' => [new FetchedResponse(200, ['content-type' => 'text/html'], '<html></html>')],
            'client_id mismatch' => [new FetchedResponse(
                200,
                ['content-type' => 'application/json'],
                (string)json_encode([
                    'client_id' => 'https://elsewhere.example/c',
                    'client_name' => 'X',
                    'redirect_uris' => ['https://claude.ai/cb'],
                ]),
            )],
            'no usable redirect URI' => [new FetchedResponse(
                200,
                ['content-type' => 'application/json'],
                (string)json_encode([
                    'client_id' => self::CLAUDE,
                    'client_name' => 'X',
                    'redirect_uris' => ['javascript:alert(1)'],
                ]),
            )],
        ];
    }

    #[DataProvider('definiteRejections')]
    public function testDefiniteRejectionsAreStillRemembered(FetchedResponse $rejection): void
    {
        $resolver = $this->limited(5);
        $this->transport->responses[self::CLAUDE] = $rejection;

        for ($i = 0; $i < 2; $i++) {
            try {
                $resolver->resolve(self::CLAUDE);
                $this->fail('Resolved a rejected client.');
            } catch (OAuthException $e) {
                $this->assertFalse($e->temporary);
            }
        }

        $this->assertCount(1, $this->transport->requests);
    }

    public function testRememberedFailuresDoNotConsumeTheBudget(): void
    {
        $resolver = $this->limited(1);
        $this->transport->responses[self::CLAUDE] = new FetchedResponse(404, [], '');
        for ($i = 0; $i < 3; $i++) {
            try {
                $resolver->resolve(self::CLAUDE, '203.0.113.1');
            } catch (OAuthException $e) {
                $this->assertSame(401, $e->status);
            }
        }
    }

    public function testAStaleClientIsStillServedFromARememberedTemporaryFailure(): void
    {
        $resolver = $this->limited(5);
        $first = $resolver->resolve(self::CLAUDE);
        $this->clock->advance(601);
        $this->transport->responses[self::CLAUDE] = new RuntimeException('down');

        $this->assertSame($first?->id, $resolver->resolve(self::CLAUDE)?->id);
        $this->assertSame($first?->id, $resolver->resolve(self::CLAUDE)?->id);
        $this->assertCount(2, $this->transport->requests);
    }

    public function testATemporaryFailureRememberedForAStaleCopyNeverRejectsOnItsOwn(): void
    {
        $resolver = $this->limited(5);
        $first = $resolver->resolve(self::CLAUDE);
        $this->clock->advance(600 + 86400 - 30);
        $this->transport->responses[self::CLAUDE] = new RuntimeException('down');
        $this->assertSame($first?->id, $resolver->resolve(self::CLAUDE)?->id);
        $this->clock->advance(40);

        try {
            $resolver->resolve(self::CLAUDE);
            $this->fail('Served a copy past the stale-if-error bound.');
        } catch (OAuthException $e) {
            $this->assertTrue($e->temporary);
        }
        $this->assertCount(3, $this->transport->requests);
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

    public function testRevocationDuringTheFetchIsKept(): void
    {
        $first = $this->resolver()->resolve(self::CLAUDE);
        $this->assertNotNull($first);
        $this->clock->advance(601);
        $this->transport->onGet = fn() => $this->storage->saveClient($first->withRevokedAt($this->clock->now()));

        $client = $this->resolver()->resolve(self::CLAUDE);

        $this->assertTrue($client?->isRevoked());
        $this->assertTrue($this->storage->findClientByClientId(self::CLAUDE)?->isRevoked());
    }

    /**
     * @return array<string, array{\Throwable|\CakeDC\OAuth\Server\Client\Cimd\FetchedResponse}>
     */
    public static function temporaryFailures(): array
    {
        return [
            'network error' => [new RuntimeException('down')],
            'http 503' => [new FetchedResponse(503, [], '')],
            'http 429' => [new FetchedResponse(429, [], '')],
        ];
    }

    #[DataProvider('temporaryFailures')]
    public function testServesTheStoredClientWhenARefetchFailsTemporarily(Throwable|FetchedResponse $failure): void
    {
        $first = $this->resolver()->resolve(self::CLAUDE);
        $this->clock->advance(601 + 86400 - 10);
        $this->transport->responses[self::CLAUDE] = $failure;

        $this->assertSame($first?->id, $this->resolver()->resolve(self::CLAUDE)?->id);
    }

    public function testARevocationDuringAFailingFetchIsHonoured(): void
    {
        $first = $this->resolver()->resolve(self::CLAUDE);
        $this->assertNotNull($first);
        $this->clock->advance(601);
        $this->transport->responses[self::CLAUDE] = new RuntimeException('down');
        $this->transport->onGet = fn() => $this->storage->saveClient($first->withRevokedAt($this->clock->now()));

        $this->assertTrue($this->resolver()->resolve(self::CLAUDE)?->isRevoked());
    }

    public function testDefiniteRejectionsTakeEffectAtOnce(): void
    {
        $this->resolver()->resolve(self::CLAUDE);
        $this->clock->advance(601);
        $good = (array)json_decode((string)$this->transport->responses[self::CLAUDE]->body, true);

        $rejections = [
            'http 404' => fn() => $this->transport->responses[self::CLAUDE] = new FetchedResponse(404, [], ''),
            'http 410' => fn() => $this->transport->responses[self::CLAUDE] = new FetchedResponse(410, [], ''),
            'client_id mismatch' => fn() => $this->transport->serve(self::CLAUDE, ['client_id' => 'https://x.example/y'] + $good),
        ];
        foreach ($rejections as $name => $arrange) {
            $arrange();
            try {
                $this->resolver()->resolve(self::CLAUDE);
                $this->fail('Served a stale client after: ' . $name);
            } catch (OAuthException $e) {
                $this->assertSame('invalid_client', $e->error, $name);
            }
        }

        $removed = new ClientResolver(
            $this->storage,
            $this->clock,
            new MetadataDocumentFetcher(new FakeDns(), $this->transport, 5, 10240, ['other.example']),
        );
        $this->expectException(OAuthException::class);
        $removed->resolve(self::CLAUDE);
    }

    public function testAFailingRefetchPastTheGraceWindowThrows(): void
    {
        $this->resolver()->resolve(self::CLAUDE);
        $this->clock->advance(600 + 86400 + 1);
        $this->transport->responses[self::CLAUDE] = new RuntimeException('down');

        $this->expectException(OAuthException::class);
        $this->resolver()->resolve(self::CLAUDE);
    }

    public function testAFailingFirstFetchThrows(): void
    {
        $this->transport->responses[self::CLAUDE] = new RuntimeException('down');

        $this->expectException(OAuthException::class);
        $this->resolver()->resolve(self::CLAUDE);
    }

    public function testASaveFailureForTheSameRowIsNotSwallowed(): void
    {
        $storage = new FlakyClientRepository();
        $resolver = new ClientResolver(
            $storage,
            $this->clock,
            new MetadataDocumentFetcher(new FakeDns(), $this->transport),
        );
        $resolver->resolve(self::CLAUDE);
        $this->clock->advance(601);
        $storage->failSave = true;

        $this->expectException(RuntimeException::class);
        $resolver->resolve(self::CLAUDE);
    }

    public function testTheFirstFetchRaceReturnsTheWinner(): void
    {
        $storage = new FlakyClientRepository();
        $winner = Fixtures::client(['clientId' => self::CLAUDE, 'type' => ClientType::MetadataDocument]);
        $storage->raceWinner = $winner;
        $resolver = new ClientResolver(
            $storage,
            $this->clock,
            new MetadataDocumentFetcher(new FakeDns(), $this->transport),
        );

        $this->assertSame($winner->id, $resolver->resolve(self::CLAUDE)?->id);
    }

    public function testPrivateSchemesAreRefusedForDocumentsUnlessEnabled(): void
    {
        $url = 'https://claude.ai/oauth/native';
        $this->transport->serve($url, [
            'client_id' => $url,
            'client_name' => 'Native',
            'application_type' => 'native',
            'redirect_uris' => ['com.example.app:/oauth', 'cursor://anysphere.cursor/oauth'],
        ]);
        $enabled = new ClientResolver(
            new InMemoryStorage(),
            $this->clock,
            new MetadataDocumentFetcher(new FakeDns(), $this->transport),
            300,
            86400,
            true,
        );
        $client = $enabled->resolve($url);
        $this->assertSame(ApplicationType::Native, $client?->applicationType);
        $this->assertSame(['com.example.app:/oauth', 'cursor://anysphere.cursor/oauth'], $client?->redirectUris);

        $this->expectExceptionMessage('no usable redirect_uris');
        $this->resolver()->resolve($url);
    }

    public function testTheCacheTimeHasAnUpperClamp(): void
    {
        $this->transport->serve(self::CLAUDE, [
            'client_id' => self::CLAUDE,
            'client_name' => 'Claude',
            'redirect_uris' => ['https://claude.ai/api/mcp/auth_callback'],
        ], 'max-age=999999');

        $client = $this->resolver()->resolve(self::CLAUDE);

        $this->assertEquals($this->clock->now()->modify('+86400 seconds'), $client?->metadataExpiresAt);
    }

    public function testARefetchAppliesDocumentChangesKeepingIdentity(): void
    {
        $first = $this->resolver()->resolve(self::CLAUDE);
        $this->transport->serve(self::CLAUDE, [
            'client_id' => self::CLAUDE,
            'client_name' => 'Claude 2',
            'redirect_uris' => ['https://claude.ai/new/callback'],
        ]);
        $this->clock->advance(601);

        $second = $this->resolver()->resolve(self::CLAUDE);

        $this->assertNotNull($first);
        $this->assertSame($first->id, $second?->id);
        $this->assertEquals($first->createdAt, $second?->createdAt);
        $this->assertSame(['https://claude.ai/new/callback'], $second?->redirectUris);
        $this->assertSame('Claude 2', $second?->name);
    }

    public function testInvalidScopeSyntaxRejectsTheDocument(): void
    {
        $this->transport->serve(self::CLAUDE, [
            'client_id' => self::CLAUDE,
            'client_name' => 'Claude',
            'redirect_uris' => ['https://claude.ai/api/mcp/auth_callback'],
            'scope' => 'a"b',
        ]);

        $this->expectException(OAuthException::class);
        $this->resolver()->resolve(self::CLAUDE);
    }

    public function testUnusableNamesFallBackToTheHostAndBadUrlsAreDropped(): void
    {
        $this->transport->serve(self::CLAUDE, [
            'client_id' => self::CLAUDE,
            'client_name' => "Evil\nName",
            'redirect_uris' => ['https://claude.ai/api/mcp/auth_callback'],
            'client_uri' => 'https://',
            'logo_uri' => 'https://%65xample.com/logo.png',
        ]);

        $client = $this->resolver()->resolve(self::CLAUDE);

        $this->assertSame('claude.ai', $client?->name);
        $this->assertNull($client?->clientUri);
        $this->assertNull($client?->logoUri);
    }

    public function testLongMultibyteNamesAreTruncatedByCharacters(): void
    {
        $this->transport->serve(self::CLAUDE, [
            'client_id' => self::CLAUDE,
            'client_name' => str_repeat('é', 300),
            'redirect_uris' => ['https://claude.ai/api/mcp/auth_callback'],
        ]);

        $this->assertSame(str_repeat('é', 255), $this->resolver()->resolve(self::CLAUDE)?->name);
    }
}
