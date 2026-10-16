<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Token;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Config\Lifetimes;
use CakeDC\OAuth\Server\Event\RefreshTokenReused;
use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Scope\ScopeResolver;
use CakeDC\OAuth\Server\Storage\InMemory\InMemoryStorage;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\RecordingEventDispatcher;
use CakeDC\OAuth\Server\Testing\FrozenClock;
use CakeDC\OAuth\Server\Token\IssuedTokens;
use CakeDC\OAuth\Server\Token\RefreshTokenRotator;
use CakeDC\OAuth\Server\Token\Token;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use CakeDC\OAuth\Server\Token\TokenIssuer;
use CakeDC\OAuth\Server\Token\TokenRevoker;
use PHPUnit\Framework\TestCase;

class RefreshTokenRotatorTest extends TestCase
{
    private InMemoryStorage $storage;

    private FrozenClock $clock;

    private RecordingEventDispatcher $events;

    private TokenIssuer $issuer;

    private Client $client;

    protected function setUp(): void
    {
        $this->storage = new InMemoryStorage();
        $this->clock = new FrozenClock();
        $this->events = new RecordingEventDispatcher();
        $this->issuer = new TokenIssuer($this->storage, new TokenGenerator(), $this->clock, $this->events, new Lifetimes());
        $this->client = Fixtures::client();
    }

    private function rotator(int $grace = 30): RefreshTokenRotator
    {
        return new RefreshTokenRotator(
            $this->storage,
            $this->issuer,
            new TokenRevoker($this->storage, $this->clock, $this->events),
            new ScopeResolver(),
            Fixtures::resources(),
            $this->clock,
            $this->events,
            $grace,
        );
    }

    private function initial(array $scopes = ['content:write']): IssuedTokens
    {
        return $this->issuer->issue(
            $this->client,
            '42',
            SubjectType::User,
            Fixtures::resources()->defaultResource(),
            $scopes,
            'family-1',
            true,
        );
    }

    private function assertInvalidGrant(callable $call, string $message = ''): void
    {
        try {
            $call();
            $this->fail('Rotated');
        } catch (OAuthException $e) {
            $this->assertSame('invalid_grant', $e->error);
            $this->assertStringContainsString($message, $e->getMessage());
        }
    }

    /**
     * Tokens of the family that still work: active and, for refresh tokens, not rotated yet.
     *
     * @return list<\CakeDC\OAuth\Server\Token\Token>
     */
    private function live(): array
    {
        return array_values(array_filter(
            $this->storage->findTokensByFamily('family-1'),
            fn(Token $t): bool => $t->isActive($this->clock->now()) && $t->usedAt === null,
        ));
    }

    public function testRotatesIntoTheSameFamily(): void
    {
        $initial = $this->initial();
        $this->clock->advance(60);

        $rotated = $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);

        $this->assertSame('family-1', $rotated->access->familyId);
        $this->assertSame($initial->refresh?->id, $rotated->refresh?->parentId);
        $this->assertSame(['content:write'], $rotated->access->scopes);
        $this->assertNotNull($this->storage->findTokenById((string)$initial->refresh?->id)?->usedAt);
    }

    public function testScopesMayOnlyNarrow(): void
    {
        $initial = $this->initial();

        $narrow = $this->rotator()->rotate($this->client, (string)$initial->refreshToken, Fixtures::MCP . '/', ['content:read']);
        $this->assertSame(['content:read'], $narrow->access->scopes);

        $this->expectException(OAuthException::class);
        $this->rotator()->rotate($this->client, (string)$narrow->refreshToken, null, ['content:publish']);
    }

    public function testScopesTheResourceNoLongerDeclaresAreNotReissued(): void
    {
        $initial = $this->initial(['content:read', 'legacy:scope']);

        $rotated = $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);

        $this->assertSame(['content:read'], $rotated->access->scopes);
        $this->assertSame(['content:read'], $rotated->refresh?->scopes);
    }

    public function testScopesTheClientMayNoLongerHoldAreNotReissued(): void
    {
        $client = Fixtures::client(['scopes' => ['content:read']]);
        $initial = $this->issuer->issue(
            $client,
            '42',
            SubjectType::User,
            Fixtures::resources()->defaultResource(),
            ['content:read', 'content:write'],
            'family-1',
            true,
        );

        $rotated = $this->rotator()->rotate($client, (string)$initial->refreshToken, null, []);

        $this->assertSame(['content:read'], $rotated->access->scopes);
    }

    public function testRejectsTokensItShouldNotRotate(): void
    {
        $initial = $this->initial();

        $this->assertInvalidGrant(fn() => $this->rotator()->rotate(Fixtures::client(), (string)$initial->refreshToken, null, []));
        $this->assertInvalidGrant(fn() => $this->rotator()->rotate($this->client, $initial->accessToken, null, []));
        $this->assertInvalidGrant(fn() => $this->rotator()->rotate($this->client, 'unknown', null, []));

        try {
            $this->rotator()->rotate($this->client, (string)$initial->refreshToken, Fixtures::API, []);
            $this->fail('Rotated for another resource');
        } catch (OAuthException $e) {
            $this->assertSame('invalid_target', $e->error);
        }

        $this->clock->advance(2592001);
        $this->assertInvalidGrant(fn() => $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []));
    }

    public function testLosingAConcurrentRotationUsesTheGracePath(): void
    {
        $initial = $this->initial();
        $winner = $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);
        $this->clock->advance(5);

        $loser = $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);

        $this->assertNotNull($this->storage->findTokenById($winner->access->id)?->revokedAt);
        $this->assertNotNull($this->storage->findTokenById((string)$winner->refresh?->id)?->revokedAt);
        $this->assertSame(
            [$initial->access->id, $loser->access->id, (string)$loser->refresh?->id],
            array_map(fn(Token $t): string => $t->id, $this->live()),
        );
        $this->assertSame([], $this->events->ofType(RefreshTokenReused::class));
    }

    public function testARotationStillInFlightAsksToRetry(): void
    {
        $initial = $this->initial();
        $this->storage->markTokenUsed((string)$initial->refresh?->id, $this->clock->now());

        $this->assertInvalidGrant(
            fn() => $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []),
            'try again',
        );
        $this->assertCount(1, $this->live());
    }

    public function testReuseAfterTheGraceWindowRevokesTheFamily(): void
    {
        $initial = $this->initial();
        $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);
        $this->clock->advance(31);

        $this->assertInvalidGrant(fn() => $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []));
        $this->assertSame([], $this->live());
        $this->assertCount(1, $this->events->ofType(RefreshTokenReused::class));
    }

    public function testReuseAfterTheNewPairWasUsedRevokesTheFamily(): void
    {
        $initial = $this->initial();
        $second = $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);
        $this->rotator()->rotate($this->client, (string)$second->refreshToken, null, []);

        $this->assertInvalidGrant(fn() => $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []));
        $this->assertSame([], $this->live());
    }

    public function testWithoutGraceAnyReuseRevokesTheFamily(): void
    {
        $initial = $this->initial();
        $this->rotator(0)->rotate($this->client, (string)$initial->refreshToken, null, []);

        $this->assertInvalidGrant(fn() => $this->rotator(0)->rotate($this->client, (string)$initial->refreshToken, null, []));
        $this->assertSame([], $this->live());
    }
}
