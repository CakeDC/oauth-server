<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Token;

use CakeDC\OAuth\Server\Config\Lifetimes;
use CakeDC\OAuth\Server\Event\TokenIssued;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Storage\InMemory\InMemoryStorage;
use CakeDC\OAuth\Server\Support\Time;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\RecordingEventDispatcher;
use CakeDC\OAuth\Server\Testing\FrozenClock;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use CakeDC\OAuth\Server\Token\TokenIssuer;
use CakeDC\OAuth\Server\Token\TokenType;
use PHPUnit\Framework\TestCase;

class TokenIssuerTest extends TestCase
{
    private InMemoryStorage $storage;

    private FrozenClock $clock;

    private RecordingEventDispatcher $events;

    private TokenIssuer $issuer;

    protected function setUp(): void
    {
        $this->storage = new InMemoryStorage();
        $this->clock = new FrozenClock();
        $this->events = new RecordingEventDispatcher();
        $this->issuer = new TokenIssuer(
            $this->storage,
            new TokenGenerator('kvg'),
            $this->clock,
            $this->events,
            new Lifetimes(access: 3600, refresh: 2592000, family: 31536000),
        );
    }

    public function testIssuesAnAccessAndRefreshPair(): void
    {
        $client = Fixtures::client();
        $issued = $this->issuer->issue(
            $client,
            '42',
            SubjectType::User,
            Fixtures::resources()->defaultResource(),
            ['content:write'],
            'family-1',
            true,
        );

        $this->assertStringStartsWith('kvg_at_', $issued->accessToken);
        $this->assertStringStartsWith('kvg_rt_', (string)$issued->refreshToken);
        $access = $this->storage->findTokenByHash(TokenGenerator::hash($issued->accessToken));
        $refresh = $this->storage->findTokenByHash(TokenGenerator::hash((string)$issued->refreshToken));
        $this->assertSame(TokenType::Access, $access?->type);
        $this->assertSame(TokenType::Refresh, $refresh?->type);
        $this->assertSame('family-1', $refresh?->familyId);
        $this->assertSame($client->id, $access?->clientInternalId);
        $this->assertEquals(Time::plus($this->clock->now(), 3600), $access?->expiresAt);
        $this->assertEquals(Time::plus($this->clock->now(), 2592000), $refresh?->expiresAt);
        $this->assertCount(2, $this->events->ofType(TokenIssued::class));

        $this->assertSame([
            'access_token' => $issued->accessToken,
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'scope' => 'content:write',
            'refresh_token' => $issued->refreshToken,
        ], $issued->toResponse());
    }

    public function testScopesAreDeduplicatedKeepingOrder(): void
    {
        $resource = Fixtures::resources()->defaultResource();
        $issued = $this->issuer->issue(
            null,
            '42',
            SubjectType::User,
            $resource,
            ['content:write', 'content:read', 'content:write'],
            'f',
            true,
        );
        $this->assertSame(['content:write', 'content:read'], $issued->access->scopes);
        $this->assertSame(['content:write', 'content:read'], $issued->refresh?->scopes);
        $this->assertSame('content:write content:read', $issued->toResponse()['scope']);

        $personal = $this->issuer->issuePersonal(
            '42',
            $resource,
            ['content:read', 'content:read'],
            'CI',
            Time::plus($this->clock->now(), 60),
        );
        $this->assertSame(['content:read'], $personal['token']->scopes);
    }

    public function testWithoutRefresh(): void
    {
        $issued = $this->issuer->issue(null, 'svc', SubjectType::Client, Fixtures::resources()->defaultResource(), [], 'f', false);

        $this->assertNull($issued->refreshToken);
        $this->assertArrayNotHasKey('refresh_token', $issued->toResponse());
        $this->assertSame('', $issued->toResponse()['scope']);
    }

    public function testTheFamilyLifetimeCapsRefreshTokens(): void
    {
        $resource = Fixtures::resources()->defaultResource();
        $started = Time::plus($this->clock->now(), -31536000 + 100);

        $capped = $this->issuer->issue(null, '42', SubjectType::User, $resource, [], 'f', true, 'parent', $started);
        $this->assertEquals(Time::plus($this->clock->now(), 100), $capped->refresh?->expiresAt);
        $this->assertSame('parent', $capped->refresh?->parentId);
        $this->assertSame('parent', $capped->access->parentId);

        $over = $this->issuer->issue(null, '42', SubjectType::User, $resource, [], 'f', true, null, Time::plus($started, -200));
        $this->assertNull($over->refreshToken);
    }

    public function testIssuesPersonalTokens(): void
    {
        $expires = Time::plus($this->clock->now(), 86400);
        $result = $this->issuer->issuePersonal('42', Fixtures::resources()->defaultResource(), ['content:read'], 'CI', $expires);

        $this->assertStringStartsWith('kvg_pat_', $result['value']);
        $this->assertSame(TokenType::Personal, $result['token']->type);
        $this->assertSame('CI', $result['token']->name);
        $this->assertNull($result['token']->clientInternalId);
        $this->assertEquals($expires, $result['token']->expiresAt);
        $this->assertNotNull($this->storage->findTokenById($result['token']->id));
    }
}
