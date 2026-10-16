<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Connections;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Config\Lifetimes;
use CakeDC\OAuth\Server\Connections\ConnectionService;
use CakeDC\OAuth\Server\Event\NullEventDispatcher;
use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Grant\Consent;
use CakeDC\OAuth\Server\Grant\ConsentService;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Storage\InMemory\InMemoryStorage;
use CakeDC\OAuth\Server\Test\Support\FakeUsers;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Testing\FrozenClock;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use CakeDC\OAuth\Server\Token\TokenIssuer;
use CakeDC\OAuth\Server\Token\TokenRevoker;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class ConnectionServiceTest extends TestCase
{
    private InMemoryStorage $storage;

    private FrozenClock $clock;

    private FakeUsers $users;

    private TokenIssuer $issuer;

    private ConnectionService $service;

    private ResourceOwner $ada;

    protected function setUp(): void
    {
        $this->storage = new InMemoryStorage();
        $this->clock = new FrozenClock();
        $this->users = new FakeUsers();
        $events = new NullEventDispatcher();
        $this->issuer = new TokenIssuer($this->storage, new TokenGenerator(), $this->clock, $events, new Lifetimes());
        $this->service = new ConnectionService(
            $this->storage,
            $this->storage,
            $this->storage,
            $this->issuer,
            new TokenRevoker($this->storage, $this->clock, $events),
            Fixtures::resources(),
            $this->users,
            $this->clock,
            30 * 86400,
        );
        $this->ada = $this->users->users['42'];
    }

    private function connect(string $family, string $subject = '42'): Client
    {
        $client = Fixtures::client(['name' => 'App ' . $family]);
        $this->storage->saveClient($client);
        $this->issuer->issue($client, $subject, SubjectType::User, Fixtures::resources()->defaultResource(), ['content:read'], $family, true);
        $this->storage->saveConsent(new Consent('c-' . $family, $subject, $client->id, Fixtures::MCP, ['content:read'], $this->clock->now(), $this->clock->now()));

        return $client;
    }

    public function testListsOneConnectionPerFamilyNewestFirst(): void
    {
        $this->connect('first');
        $this->clock->advance(100);
        $second = $this->connect('second');
        $this->connect('foreign', '43');
        $this->service->createPersonalToken($this->ada, 'CI', Fixtures::MCP, ['content:read'], 7);

        $connections = $this->service->connections($this->ada);

        $this->assertSame(['second', 'first'], array_map(fn($c) => $c->familyId, $connections));
        $this->assertSame($second->id, $connections[0]->client->id);
        $this->assertSame(Fixtures::MCP, $connections[0]->resource);
        $this->assertSame(['content:read'], $connections[0]->scopes);
        $this->assertEquals($this->clock->now(), $connections[0]->connectedAt);
        $this->assertNull($connections[0]->lastUsedAt);
    }

    public function testRevokingAConnectionRevokesItsFamilyAndConsent(): void
    {
        $client = $this->connect('first');
        $this->connect('foreign', '43');

        $this->assertFalse($this->service->revokeConnection($this->ada, 'foreign'));
        $this->assertTrue($this->service->revokeConnection($this->ada, 'first'));

        $this->assertSame([], $this->service->connections($this->ada));
        $this->assertNull($this->storage->findConsent('42', $client->id, Fixtures::MCP));
        $this->assertNotNull($this->storage->findConsent('43', $this->storage->findTokensByFamily('foreign')[0]->clientInternalId ?? '', Fixtures::MCP));
    }

    public function testCreatesListsAndRevokesPersonalTokens(): void
    {
        $result = $this->service->createPersonalToken($this->ada, '  Deploy script ', 'https://example.com/mcp/', ['content:write'], 30);

        $this->assertSame('Deploy script', $result['token']->name);
        $tokens = $this->service->personalTokens($this->ada);
        $this->assertCount(1, $tokens);
        $this->assertSame([], $this->service->personalTokens($this->users->users['43']));

        $this->assertFalse($this->service->revokePersonalToken($this->users->users['43'], $tokens[0]->id));
        $this->assertTrue($this->service->revokePersonalToken($this->ada, $tokens[0]->id));
        $this->assertSame([], $this->service->personalTokens($this->ada));
    }

    /**
     * @return array<string, array{string, string, list<string>, int, string}>
     */
    public static function invalidPersonalTokens(): array
    {
        return [
            'no name' => [' ', Fixtures::MCP, ['content:read'], 7, 'invalid_request'],
            'long name' => [str_repeat('n', 101), Fixtures::MCP, ['content:read'], 7, 'invalid_request'],
            'long multibyte name' => [str_repeat("\u{e9}", 101), Fixtures::MCP, ['content:read'], 7, 'invalid_request'],
            'newline in name' => ["a\nb", Fixtures::MCP, ['content:read'], 7, 'invalid_request'],
            'tab in name' => ["a\tb", Fixtures::MCP, ['content:read'], 7, 'invalid_request'],
            'right-to-left override' => ["CI\u{202E}", Fixtures::MCP, ['content:read'], 7, 'invalid_request'],
            'zero width space' => ["C\u{200B}I", Fixtures::MCP, ['content:read'], 7, 'invalid_request'],
            'only a no-break space' => ["\u{00A0}", Fixtures::MCP, ['content:read'], 7, 'invalid_request'],
            'only format characters' => ["\u{200B}\u{2060}", Fixtures::MCP, ['content:read'], 7, 'invalid_request'],
            'invalid utf8 name' => ["a\xff", Fixtures::MCP, ['content:read'], 7, 'invalid_request'],
            'unknown resource' => ['CI', 'https://other.example', ['content:read'], 7, 'invalid_target'],
            'no scope' => ['CI', Fixtures::MCP, [], 7, 'invalid_scope'],
            'scope above the owner' => ['CI', Fixtures::MCP, ['content:publish'], 7, 'invalid_scope'],
            'zero days' => ['CI', Fixtures::MCP, ['content:read'], 0, 'invalid_request'],
            'negative days' => ['CI', Fixtures::MCP, ['content:read'], -3, 'invalid_request'],
            'one day over the maximum' => ['CI', Fixtures::MCP, ['content:read'], 31, 'invalid_request'],
        ];
    }

    #[DataProvider('invalidPersonalTokens')]
    public function testValidatesPersonalTokens(string $name, string $resource, array $scopes, int $days, string $error): void
    {
        $this->users->scopes['42'] = ['content:write'];

        try {
            $this->service->createPersonalToken($this->ada, $name, $resource, $scopes, $days);
            $this->fail('Created');
        } catch (OAuthException $e) {
            $this->assertSame($error, $e->error);
        }
    }

    public function testCreatableScopesFollowTheOwner(): void
    {
        $this->users->scopes['42'] = ['content:write'];

        $creatable = $this->service->creatableScopes($this->ada);

        $this->assertSame(['content:read' => 'Read your posts', 'content:write' => 'Edit drafts'], $creatable[Fixtures::MCP]['scopes']);
        $this->assertSame('Example MCP', $creatable[Fixtures::MCP]['name']);
        $this->assertArrayNotHasKey(Fixtures::API, $creatable);
        $this->assertSame(30, $this->service->maxPersonalDays());
    }

    public function testClientTypedOwnersCannotCreateAnything(): void
    {
        $impostor = new ResourceOwner('42', 'Impostor', [], SubjectType::Client);

        $this->assertSame([], $this->service->creatableScopes($impostor));
    }

    public function testAcceptsTheMaximumLifetimeAndSetsAFutureExpiry(): void
    {
        $result = $this->service->createPersonalToken($this->ada, 'CI', Fixtures::MCP, ['content:read'], 30);

        $this->assertEquals($this->clock->now()->modify('+30 days'), $result['token']->expiresAt);
    }

    public function testCannotRevokeAPersonalTokenThroughConnectionsOrViceVersa(): void
    {
        $this->connect('first');
        $personal = $this->service->createPersonalToken($this->ada, 'CI', Fixtures::MCP, ['content:read'], 7);

        $this->assertFalse($this->service->revokeConnection($this->ada, $personal['token']->familyId));
        $this->assertFalse($this->service->revokePersonalToken($this->ada, $this->storage->findTokensByFamily('first')[0]->id));
        $this->assertFalse($this->service->revokeConnection($this->ada, 'no-such-family'));
        $this->assertFalse($this->service->revokePersonalToken($this->ada, 'no-such-token'));
        $this->assertCount(1, $this->service->connections($this->ada));
        $this->assertCount(1, $this->service->personalTokens($this->ada));
    }

    public function testSubjectComparisonIsCaseSensitive(): void
    {
        $this->connect('mixed', 'abc');
        $upper = new ResourceOwner('ABC', 'Upper', []);

        $this->assertFalse($this->service->revokeConnection($upper, 'mixed'));
        $this->assertSame([], $this->service->connections($upper));
    }

    public function testClientTypedOwnersGetNothingAndCanDoNothing(): void
    {
        $this->connect('first');
        $personal = $this->service->createPersonalToken($this->ada, 'CI', Fixtures::MCP, ['content:read'], 7);
        $impostor = new ResourceOwner('42', 'Impostor', [], SubjectType::Client);

        $this->assertSame([], $this->service->connections($impostor));
        $this->assertSame([], $this->service->personalTokens($impostor));
        $this->assertFalse($this->service->revokeConnection($impostor, 'first'));
        $this->assertFalse($this->service->revokePersonalToken($impostor, $personal['token']->id));
        $this->assertCount(1, $this->service->connections($this->ada));
        $this->assertCount(1, $this->service->personalTokens($this->ada));
        try {
            $this->service->createPersonalToken($impostor, 'CI', Fixtures::MCP, ['content:read'], 7);
            $this->fail('Created');
        } catch (OAuthException $e) {
            $this->assertSame('invalid_request', $e->error);
        }
        $this->assertCount(1, $this->service->personalTokens($this->ada));
    }

    public function testRevokingADeadFamilyKeepsTheNewerConsent(): void
    {
        $client = $this->connect('old');
        $this->assertTrue($this->service->revokeConnection($this->ada, 'old'));
        $this->issuer->issue($client, '42', SubjectType::User, Fixtures::resources()->defaultResource(), ['content:read'], 'new', true);
        $this->storage->saveConsent(new Consent('c-new', '42', $client->id, Fixtures::MCP, ['content:read'], $this->clock->now(), $this->clock->now()));

        $this->assertFalse($this->service->revokeConnection($this->ada, 'old'));
        $this->assertNotNull($this->storage->findConsent('42', $client->id, Fixtures::MCP));
        $this->assertCount(1, $this->service->connections($this->ada));
    }

    public function testRevokingAPersonalTokenTwiceReturnsFalse(): void
    {
        $result = $this->service->createPersonalToken($this->ada, 'CI', Fixtures::MCP, ['content:read'], 7);

        $this->assertTrue($this->service->revokePersonalToken($this->ada, $result['token']->id));
        $this->assertFalse($this->service->revokePersonalToken($this->ada, $result['token']->id));
    }

    public function testAcceptsAHundredMultibyteCharacters(): void
    {
        $result = $this->service->createPersonalToken($this->ada, str_repeat("\u{e9}", 100), Fixtures::MCP, ['content:read'], 7);

        $this->assertSame(100, mb_strlen((string)$result['token']->name));
    }

    public function testAcceptsAHundredJapaneseCharacters(): void
    {
        $name = str_repeat("\u{3042}", 100);

        $result = $this->service->createPersonalToken($this->ada, $name, Fixtures::MCP, ['content:read'], 7);

        $this->assertSame($name, $result['token']->name);
    }

    public function testRevokingAConnectionMakesTheClientUntrustedAgain(): void
    {
        $client = $this->connect('first');
        $consents = new ConsentService($this->storage, $this->clock, new NullEventDispatcher());
        $this->assertTrue($consents->hasConsented($this->ada, $client));

        $this->service->revokeConnection($this->ada, 'first');

        $this->assertFalse($consents->hasConsented($this->ada, $client));
    }

    public function testConnectionsSkipRevokedClientsExpiredFamiliesAndClientCredentials(): void
    {
        $revoked = $this->connect('revoked');
        $this->storage->saveClient($revoked->withRevokedAt($this->clock->now()));
        $this->connect('expired');
        $this->clock->advance(366 * 86400);
        $live = $this->connect('live');
        $cc = Fixtures::client(['name' => 'Machine']);
        $this->storage->saveClient($cc);
        $this->issuer->issue($cc, '42', SubjectType::Client, Fixtures::resources()->defaultResource(), ['content:read'], 'cc', false);

        $this->assertSame(['live'], array_map(fn($c) => $c->familyId, $this->service->connections($this->ada)));
        $this->assertSame($live->id, $this->service->connections($this->ada)[0]->client->id);
    }

    public function testConnectedAtIsTheFamilyStartAfterRotation(): void
    {
        $client = $this->connect('first');
        $start = $this->clock->now();
        $this->clock->advance(500);
        $this->issuer->issue(
            $client,
            '42',
            SubjectType::User,
            Fixtures::resources()->defaultResource(),
            ['content:read'],
            'first',
            true,
            null,
            $start,
        );

        $connections = $this->service->connections($this->ada);

        $this->assertCount(1, $connections);
        $this->assertEquals($start, $connections[0]->connectedAt);
    }
}
