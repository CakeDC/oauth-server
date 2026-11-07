<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Token;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Config\Lifetimes;
use CakeDC\OAuth\Server\Event\RefreshTokenReused;
use CakeDC\OAuth\Server\Event\TokenIssued;
use CakeDC\OAuth\Server\Event\TokenRevoked;
use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Scope\ScopeResolver;
use CakeDC\OAuth\Server\Storage\InMemory\InMemoryStorage;
use CakeDC\OAuth\Server\Storage\TokenRepositoryInterface;
use CakeDC\OAuth\Server\Test\Support\FakeUsers;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\HiddenRotation;
use CakeDC\OAuth\Server\Test\Support\PassThroughTokens;
use CakeDC\OAuth\Server\Test\Support\RecordingEventDispatcher;
use CakeDC\OAuth\Server\Testing\FrozenClock;
use CakeDC\OAuth\Server\Token\IssuedTokens;
use CakeDC\OAuth\Server\Token\RefreshTokenRotator;
use CakeDC\OAuth\Server\Token\Token;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use CakeDC\OAuth\Server\Token\TokenIssuer;
use CakeDC\OAuth\Server\Token\TokenRevoker;
use CakeDC\OAuth\Server\Token\TokenType;
use Closure;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use Throwable;

class RefreshTokenRotatorTest extends TestCase
{
    private InMemoryStorage $storage;

    private FrozenClock $clock;

    private RecordingEventDispatcher $events;

    private TokenIssuer $issuer;

    private Client $client;

    private FakeUsers $users;

    /**
     * @var list<int> Microseconds the rotator slept, in order.
     */
    private array $sleeps = [];

    protected function setUp(): void
    {
        $this->storage = new InMemoryStorage();
        $this->clock = new FrozenClock();
        $this->events = new RecordingEventDispatcher();
        $this->issuer = new TokenIssuer($this->storage, new TokenGenerator(), $this->clock, $this->events, new Lifetimes());
        $this->client = Fixtures::client();
        $this->users = new FakeUsers();
    }

    private function rotator(int $grace = 30, ?TokenRepositoryInterface $tokens = null, ?Closure $onSleep = null): RefreshTokenRotator
    {
        return new RefreshTokenRotator(
            $tokens ?? $this->storage,
            $this->issuer,
            new TokenRevoker($this->storage, $this->storage, $this->clock, $this->events),
            new ScopeResolver(),
            Fixtures::resources(),
            $this->clock,
            $this->events,
            $this->users,
            $grace,
            'rotation-test-secret',
            200,
            function (int $microseconds) use ($onSleep): void {
                $this->sleeps[] = $microseconds;
                if ($onSleep !== null) {
                    $onSleep();
                }
            },
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

    public function testARemovedOwnerCannotRefreshAndNothingIsRevoked(): void
    {
        $initial = $this->initial();
        $this->users->remove('42');

        $this->assertInvalidGrant(
            fn() => $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []),
            'no longer has access',
        );
        $this->assertCount(2, $this->live());
        $this->assertNull($this->storage->findTokenById((string)$initial->refresh?->id)?->usedAt);

        $this->users->add('42', 'Ada');
        $rotated = $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);
        $this->assertSame('42', $rotated->access->subject);
    }

    public function testAClientTokenNeedsItsIdentityToRefresh(): void
    {
        $initial = $this->issuer->issue(
            $this->client,
            'robot',
            SubjectType::Client,
            Fixtures::resources()->defaultResource(),
            ['content:read'],
            'family-1',
            true,
        );

        $this->assertInvalidGrant(
            fn() => $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []),
        );
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

    /**
     * RFC 6749 section 6 and OAuth 2.1 section 4.3.3: the new refresh token has the scope of the one
     * presented. A requested scope narrows the access token only, so the grant is not lost.
     */
    public function testARequestedScopeNarrowsTheAccessTokenOnly(): void
    {
        $initial = $this->initial(['content:write']);

        $narrow = $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, ['content:read']);

        $this->assertSame(['content:read'], $narrow->access->scopes);
        $this->assertSame(['content:write'], $narrow->refresh?->scopes);
        $this->assertSame('content:read', $narrow->toResponse()['scope']);

        $this->clock->advance(60);
        $broad = $this->rotator()->rotate($this->client, (string)$narrow->refreshToken, null, ['content:write']);

        $this->assertSame(['content:write'], $broad->access->scopes);
        $this->assertSame(['content:write'], $broad->refresh?->scopes);
    }

    public function testTheGracePairKeepsTheGrantOfThePresentedToken(): void
    {
        $initial = $this->initial(['content:write']);
        $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, ['content:read']);
        $this->clock->advance(5);

        $retry = $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, ['content:read']);

        $this->assertSame(['content:read'], $retry->access->scopes);
        $this->assertSame(['content:write'], $retry->refresh?->scopes);
    }

    public function testScopesTheResourceNoLongerDeclaresAreNotReissued(): void
    {
        $initial = $this->initial(['content:read', 'legacy:scope']);

        $rotated = $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);

        $this->assertSame(['content:read'], $rotated->access->scopes);
        $this->assertSame(['content:read'], $rotated->refresh?->scopes);
    }

    public function testScopesTheClientMayNoLongerHoldAreNotOnTheAccessToken(): void
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
        // The client's allowance is current policy, like the owner's: checked on every use, never stored.
        $this->assertSame(['content:read', 'content:write'], $rotated->refresh?->scopes);
    }

    /**
     * The same client as $this->client, with the allowance an administrator gave it today.
     *
     * @param list<string>|null $scopes The client's scopes; null for any.
     */
    private function clientAllowed(?array $scopes): Client
    {
        return Fixtures::client(['id' => $this->client->id, 'clientId' => $this->client->clientId, 'scopes' => $scopes]);
    }

    public function testANarrowedClientRefreshesWithTheNarrowedAccessToken(): void
    {
        $initial = $this->initial(['content:write']);

        $rotated = $this->rotator()->rotate($this->clientAllowed(['content:read']), (string)$initial->refreshToken, null, []);

        $this->assertSame(['content:read'], $rotated->access->scopes);
        $this->assertSame(['content:write'], $rotated->refresh?->scopes);
        $this->assertSame('content:read', $rotated->toResponse()['scope']);
    }

    public function testAClientNarrowedToAnImpliedScopeKeepsOnlyTheMinimalSet(): void
    {
        $initial = $this->initial(['content:publish']);

        $rotated = $this->rotator()->rotate($this->clientAllowed(['content:write']), (string)$initial->refreshToken, null, []);

        $this->assertSame(['content:write'], $rotated->access->scopes);
        $this->assertSame(['content:publish'], $rotated->refresh?->scopes);
    }

    public function testAClientWidenedAgainRegainsTheGrantOnTheNextRefresh(): void
    {
        $initial = $this->initial(['content:write']);
        $narrowed = $this->rotator()->rotate($this->clientAllowed(['content:read']), (string)$initial->refreshToken, null, []);
        $this->assertSame(['content:read'], $narrowed->access->scopes);

        $this->clock->advance(60);
        $widened = $this->rotator()->rotate($this->clientAllowed(null), (string)$narrowed->refreshToken, null, []);

        $this->assertSame(['content:write'], $widened->access->scopes);
        $this->assertSame(['content:write'], $widened->refresh?->scopes);
        $this->assertSame('content:write', $widened->toResponse()['scope']);
    }

    public function testAClientNarrowedToNothingCannotRefreshAndNothingIsConsumed(): void
    {
        $initial = $this->initial(['content:write']);

        foreach ([[], ['api']] as $allowed) {
            try {
                $this->rotator()->rotate($this->clientAllowed($allowed), (string)$initial->refreshToken, null, []);
                $this->fail('Rotated');
            } catch (OAuthException $e) {
                $this->assertSame('invalid_scope', $e->error);
            }
        }
        $this->assertNull($this->storage->findTokenById((string)$initial->refresh?->id)?->usedAt);
        $this->assertCount(2, $this->live());
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

    public function testLosingAConcurrentRotationAnswersWithTheWinnersPair(): void
    {
        $initial = $this->initial();
        $winner = $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);
        $this->clock->advance(5);

        $loser = $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);

        $this->assertSame($winner->toResponse(), $loser->toResponse());
        $this->assertSame($winner->access->id, $loser->access->id);
        $this->assertSame($winner->refresh?->id, $loser->refresh?->id);
        $this->assertSame(
            [$initial->access->id, $winner->access->id, (string)$winner->refresh?->id],
            array_map(fn(Token $t): string => $t->id, $this->live()),
        );
        $this->assertSame([], $this->events->ofType(RefreshTokenReused::class));
        $this->assertCount(4, $this->events->ofType(TokenIssued::class), 'the loser issues nothing');
    }

    public function testALoserGetsThePairEvenAfterTheWinnersClientUsedTheAccessToken(): void
    {
        $initial = $this->initial();
        $winner = $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);
        $this->storage->touchToken($winner->access->id, $this->clock->now());
        $this->clock->advance(1);

        $loser = $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);

        $this->assertSame($winner->toResponse(), $loser->toResponse());
        $this->assertSame([], $this->events->ofType(RefreshTokenReused::class));
    }

    public function testASealThatDoesNotOpenFallsBackToTheGraceReissue(): void
    {
        $initial = $this->initial();
        $winner = $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);
        $this->clock->advance(5);
        $otherSecret = new RefreshTokenRotator(
            $this->storage,
            $this->issuer,
            new TokenRevoker($this->storage, $this->storage, $this->clock, $this->events),
            new ScopeResolver(),
            Fixtures::resources(),
            $this->clock,
            $this->events,
            $this->users,
            30,
            'another-secret',
        );

        $loser = $otherSecret->rotate($this->client, (string)$initial->refreshToken, null, []);

        $this->assertNotSame($winner->refreshToken, $loser->refreshToken);
        $this->assertNotNull($this->storage->findTokenById((string)$winner->refresh?->id)?->revokedAt);
        $this->assertSame([], $this->events->ofType(RefreshTokenReused::class));
    }

    public function testATamperedSealIsNotAnswered(): void
    {
        $initial = $this->initial();
        $winner = $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);
        $this->clock->advance(5);
        $tampered = new class ($this->storage) extends PassThroughTokens {
            public function findTokensByFamily(string $familyId): array
            {
                return array_map(function (Token $token): Token {
                    if ($token->rotationSeal === null) {
                        return $token;
                    }
                    $bytes = (string)base64_decode($token->rotationSeal, true);
                    $bytes[strlen($bytes) - 1] = chr(ord($bytes[strlen($bytes) - 1]) ^ 1);

                    return new Token(...array_merge(get_object_vars($token), ['rotationSeal' => base64_encode($bytes)]));
                }, parent::findTokensByFamily($familyId));
            }
        };

        $loser = $this->rotator(30, $tampered)->rotate($this->client, (string)$initial->refreshToken, null, []);

        $this->assertNotSame($winner->refreshToken, $loser->refreshToken);
        $this->assertNotSame(substr((string)$winner->refreshToken, 0, -1), substr((string)$loser->refreshToken, 0, -1));
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
        $this->assertSame(200000, array_sum($this->sleeps), 'it waits the whole budget before giving up');
    }

    public function testALoserArrivingMidRotationWaitsForTheWinnersPair(): void
    {
        $initial = $this->initial();
        $winner = $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);
        $hidden = new HiddenRotation($this->storage, (string)$initial->refresh?->id);

        $loser = $this->rotator(30, $hidden, function () use ($hidden): void {
            if (count($this->sleeps) === 2) {
                $hidden->reveal();
            }
        })->rotate($this->client, (string)$initial->refreshToken, null, []);

        $this->assertSame($winner->toResponse(), $loser->toResponse());
        $this->assertCount(2, $this->sleeps);
        $this->assertSame([], $this->events->ofType(RefreshTokenReused::class));
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

    /**
     * Runs $action the first time a rotation saves its access token, as another request would.
     */
    private function duringNextRotation(callable $action): void
    {
        $fired = false;
        $this->events->hook = function (object $event) use (&$fired, $action): void {
            if (
                !$fired && $event instanceof TokenIssued && $event->token->type === TokenType::Access
                && $event->token->parentId !== null
            ) {
                $fired = true;
                $action();
            }
        };
    }

    /**
     * Refresh tokens issued by rotating $parent that still work.
     *
     * @return list<\CakeDC\OAuth\Server\Token\Token>
     */
    private function liveChildrenOf(Token $parent): array
    {
        return array_values(array_filter(
            $this->storage->findTokensByFamily('family-1'),
            fn(Token $t): bool => $t->type === TokenType::Refresh && $t->parentId === $parent->id
                && $t->isActive($this->clock->now()) && $t->usedAt === null,
        ));
    }

    public function testALoserArrivingBeforeTheRefreshChildExistsRevokesNothing(): void
    {
        $initial = $this->initial();
        $message = null;
        $this->duringNextRotation(function () use ($initial, &$message): void {
            try {
                $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);
            } catch (OAuthException $e) {
                $message = $e->getMessage();
            }
        });

        $winner = $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);

        $this->assertStringContainsString('try again', (string)$message);
        $this->assertNull($this->storage->findTokenById($winner->access->id)?->revokedAt);
        $children = $this->liveChildrenOf($initial->refresh);
        $this->assertSame([(string)$winner->refresh?->id], array_map(fn(Token $t): string => $t->id, $children));
        $this->assertSame([], $this->events->ofType(RefreshTokenReused::class));
    }

    public function testWithoutGraceALoserInTheGapCannotLeaveTheWinnersRefreshTokenAlive(): void
    {
        $initial = $this->initial();
        $this->duringNextRotation(function () use ($initial): void {
            try {
                $this->rotator(0)->rotate($this->client, (string)$initial->refreshToken, null, []);
            } catch (OAuthException) {
            }
        });

        $this->assertInvalidGrant(fn() => $this->rotator(0)->rotate($this->client, (string)$initial->refreshToken, null, []));

        $this->assertSame([], $this->live());
    }

    public function testEveryGracePresentationGetsTheSamePairAndOneRefreshTokenLives(): void
    {
        $initial = $this->initial();
        $winner = $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);
        $this->clock->advance(5);

        $second = $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);
        $third = $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);

        $this->assertSame($winner->toResponse(), $second->toResponse());
        $this->assertSame($winner->toResponse(), $third->toResponse());
        $this->assertCount(1, $this->liveChildrenOf($initial->refresh));
        $this->assertSame([], $this->events->ofType(RefreshTokenReused::class));
    }

    public function testAGracePresentationAfterTheClientRotatedTheChildIsReuseEvenMidRotation(): void
    {
        $initial = $this->initial();
        $winner = $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);
        $this->clock->advance(5);
        $this->duringNextRotation(function () use ($initial): void {
            try {
                $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);
            } catch (OAuthException) {
            }
        });

        $this->assertInvalidGrant(fn() => $this->rotator()->rotate($this->client, (string)$winner->refreshToken, null, []));

        $this->assertSame([], $this->live());
        $this->assertCount(1, $this->events->ofType(RefreshTokenReused::class));
    }

    public function testARevocationDuringARotationRevokesTheNewPair(): void
    {
        $initial = $this->initial();
        $this->duringNextRotation(fn() => $this->storage->revokeTokenFamily('family-1', $this->clock->now()));

        $this->assertInvalidGrant(fn() => $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []));

        $this->assertSame([], $this->live());
        $this->assertSame([], array_filter(
            $this->storage->findTokensByFamily('family-1'),
            fn(Token $t): bool => $t->revokedAt === null,
        ));
    }

    public function testTheFamilyLifetimeSurvivesPruning(): void
    {
        $lifetimes = new Lifetimes();
        $start = $this->clock->now();
        $current = $this->initial();
        $lastExpiry = $current->refresh?->expiresAt;
        $days = 0;
        while ($current->refresh !== null && $days < 400) {
            $this->clock->advance(86400);
            $days++;
            try {
                $current = $this->rotator()->rotate($this->client, (string)$current->refreshToken, null, []);
            } catch (OAuthException) {
                break;
            }
            $this->storage->prune($this->clock->now(), 7 * 86400, 86400);
            if ($current->refresh !== null) {
                $lastExpiry = $current->refresh->expiresAt;
            }
        }

        $this->assertLessThan(400, $days);
        $this->assertLessThanOrEqual($start->getTimestamp() + $lifetimes->family, $lastExpiry?->getTimestamp());
    }

    public function testPresentingARevokedTokenWhileTheFamilyStillLivesIsATakeover(): void
    {
        $initial = $this->initial();
        $winner = $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);
        $this->storage->revokeToken((string)$winner->refresh?->id, $this->clock->now());
        $this->clock->advance(5);

        $this->assertInvalidGrant(fn() => $this->rotator()->rotate($this->client, (string)$winner->refreshToken, null, []));

        $this->assertSame([], $this->live());
        $this->assertCount(1, $this->events->ofType(RefreshTokenReused::class));
    }

    public function testPresentingARevokedTokenOfADeadFamilyIsPlainInvalidGrant(): void
    {
        $initial = $this->initial();
        $this->storage->revokeTokenFamily('family-1', $this->clock->now());

        $this->assertInvalidGrant(fn() => $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []));

        $this->assertSame([], $this->events->ofType(RefreshTokenReused::class));
    }

    public function testAnAccessChildThatWasUsedCountsEvenIfRevoked(): void
    {
        $initial = $this->initial();
        $winner = $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);
        $this->storage->touchToken($winner->access->id, $this->clock->now());
        $this->storage->revokeToken($winner->access->id, $this->clock->now());
        $this->clock->advance(5);

        $this->assertInvalidGrant(fn() => $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []));

        $this->assertSame([], $this->live());
        $this->assertCount(1, $this->events->ofType(RefreshTokenReused::class));
    }

    public function testTheGraceWindowIncludesExactlyGraceSecondsAndTheGracePairHasTheParent(): void
    {
        $initial = $this->initial();
        $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);
        $this->clock->advance(30);

        $loser = $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);

        $this->assertSame($initial->refresh?->id, $loser->refresh?->parentId);
        $this->assertSame($initial->refresh?->id, $loser->access->parentId);

        $second = $this->initialInOtherFamily();
        $this->rotator()->rotate($this->client, $second, null, []);
        $this->clock->advance(31);
        $this->assertInvalidGrant(fn() => $this->rotator()->rotate($this->client, $second, null, []));
    }

    private function initialInOtherFamily(): string
    {
        return (string)$this->issuer->issue(
            $this->client,
            '42',
            SubjectType::User,
            Fixtures::resources()->defaultResource(),
            ['content:write'],
            'family-2',
            true,
        )->refreshToken;
    }

    public function testAReplayWithABadScopeOrResourceStillTriggersDetection(): void
    {
        $initial = $this->initial();
        $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);
        $this->clock->advance(31);

        try {
            $this->rotator()->rotate($this->client, (string)$initial->refreshToken, Fixtures::API, ['nonsense']);
            $this->fail('Rotated');
        } catch (OAuthException $e) {
            $this->assertSame('invalid_grant', $e->error);
        }

        $this->assertSame([], $this->live());
        $this->assertCount(1, $this->events->ofType(RefreshTokenReused::class));
    }

    public function testRefusesToIssueAScopelessPair(): void
    {
        $initial = $this->initial(['legacy:scope']);

        try {
            $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);
            $this->fail('Rotated');
        } catch (Throwable $e) {
            $this->assertInstanceOf(OAuthException::class, $e);
            $this->assertSame('invalid_scope', $e->error);
        }
    }

    public function testAnOwnerWithNoScopeLeftCannotRefreshAndNothingIsConsumed(): void
    {
        $initial = $this->initial();
        $this->users->scopes['42'] = [];

        $this->assertInvalidGrant(
            fn() => $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []),
            'no longer allows any scope',
        );
        $this->assertNull($this->storage->findTokenById((string)$initial->refresh?->id)?->usedAt);
        $this->assertCount(2, $this->live());

        $this->users->scopes['42'] = null;
        $this->assertSame(['content:write'], $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, [])->access->scopes);
    }

    public function testARefreshCarriesTheScopesTheOwnerStillAllows(): void
    {
        $initial = $this->initial(['content:read', 'content:write']);
        $this->users->scopes['42'] = ['content:read'];

        $rotated = $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);

        $this->assertSame(['content:read'], $rotated->access->scopes);
        $this->assertSame(['content:read', 'content:write'], $rotated->refresh?->scopes);
        $this->assertSame('content:read', $rotated->toResponse()['scope']);
    }

    public function testTheOwnerAllowanceIsExpandedForTheCheckButNeverStored(): void
    {
        $initial = $this->initial(['content:read']);
        $this->users->scopes['42'] = ['content:publish'];

        $rotated = $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);

        $this->assertSame(['content:read'], $rotated->access->scopes);
    }

    public function testADemotionNarrowsTheGrantInsteadOfKillingIt(): void
    {
        $initial = $this->initial(['content:write']);
        $this->users->scopes['42'] = ['content:read'];

        $rotated = $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);

        $this->assertSame(['content:read'], $rotated->access->scopes);
        $this->assertSame(['content:write'], $rotated->refresh?->scopes);
        $this->assertSame('content:read', $rotated->toResponse()['scope']);
    }

    public function testAnOwnerPromotedAgainRegainsTheGrantOnTheNextRefresh(): void
    {
        $initial = $this->initial(['content:write']);
        $this->users->scopes['42'] = ['content:read'];
        $demoted = $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []);
        $this->assertSame(['content:read'], $demoted->access->scopes);

        $this->users->scopes['42'] = null;
        $this->clock->advance(60);
        $promoted = $this->rotator()->rotate($this->client, (string)$demoted->refreshToken, null, []);

        $this->assertSame(['content:write'], $promoted->access->scopes);
        $this->assertSame(['content:write'], $promoted->refresh?->scopes);
        $this->assertSame('content:write', $promoted->toResponse()['scope']);
    }

    public function testTheResultIsReducedToItsMinimalSet(): void
    {
        $initial = $this->initial(['content:write', 'content:read']);
        $this->users->scopes['42'] = ['content:read'];

        $this->assertSame(
            ['content:read'],
            $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, [])->access->scopes,
        );
    }

    public function testAnUnrestrictedOwnerKeepsTheGrantAsItIs(): void
    {
        $initial = $this->initial(['content:publish']);

        $this->assertSame(
            ['content:publish'],
            $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, [])->access->scopes,
        );
    }

    public function testNarrowingToNothingKeepsInvalidScope(): void
    {
        $initial = $this->initial(['content:read']);

        try {
            $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, ['content:write']);
            $this->fail('Rotated');
        } catch (OAuthException $e) {
            $this->assertSame('invalid_scope', $e->error);
        }
    }

    public function testAClientIdentityWithNoScopeLeftCannotRefresh(): void
    {
        $robot = new ResourceOwner('robot', 'Reporting job', null, SubjectType::Client);
        $this->users->clientIdentity = $robot;
        $initial = $this->issuer->issue(
            $this->client,
            'robot',
            SubjectType::Client,
            Fixtures::resources()->defaultResource(),
            ['content:read'],
            'family-1',
            true,
        );
        $this->users->scopes['robot'] = [];

        $this->assertInvalidGrant(
            fn() => $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []),
            'no longer allows any scope',
        );
    }

    public function testARevokedClientCannotRotate(): void
    {
        $initial = $this->initial();
        $revoked = $this->client->withRevokedAt($this->clock->now());

        try {
            $this->rotator()->rotate($revoked, (string)$initial->refreshToken, null, []);
            $this->fail('Rotated');
        } catch (OAuthException $e) {
            $this->assertSame('invalid_client', $e->error);
        }
    }

    public function testNoReuseEventWhenTheFamilyWasAlreadyRevoked(): void
    {
        $initial = $this->initial();
        $this->storage->revokeTokenFamily('family-1', $this->clock->now());
        $token = $this->storage->findTokenById((string)$initial->refresh?->id);
        $method = new ReflectionMethod(RefreshTokenRotator::class, 'detectedReuse');

        try {
            $method->invoke($this->rotator(), $this->client, $token);
            $this->fail('Answered');
        } catch (OAuthException $e) {
            $this->assertSame('invalid_grant', $e->error);
        }

        $this->assertSame([], $this->events->ofType(RefreshTokenReused::class));
    }

    public function testARevocationMidRotationIsLabelledRotationRevoked(): void
    {
        $initial = $this->initial();
        $this->duringNextRotation(fn() => $this->storage->revokeTokenFamily('family-1', $this->clock->now()));

        $this->assertInvalidGrant(fn() => $this->rotator()->rotate($this->client, (string)$initial->refreshToken, null, []));

        $reasons = array_map(fn(TokenRevoked $e): string => $e->reason, $this->events->ofType(TokenRevoked::class));
        $this->assertSame(['rotation_revoked'], $reasons);
        $this->assertSame([], $this->events->ofType(RefreshTokenReused::class));
    }
}
