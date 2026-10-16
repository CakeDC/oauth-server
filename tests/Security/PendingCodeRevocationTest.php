<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Security;

use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use CakeDC\OAuth\Server\Test\Support\ThrowingTouchTokens;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use CakeDC\OAuth\Server\Token\TokenRevoker;
use Closure;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

/**
 * A code issued just before a revocation must not open a new family afterwards: revoking a person, a
 * connection or a client deletes the codes that were not exchanged yet.
 */
class PendingCodeRevocationTest extends TestCase
{
    public function testRevokingAPersonDeletesTheirPendingCodes(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $code = $harness->authorizationCode($client);
        $otherPerson = $harness->authorizationCode($client, [], '43');

        $harness->server->tokenRevoker()->revokeAllForSubject('42');
        $harness->clock->advance(30);

        $response = $harness->exchange($client, $code);
        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('invalid_grant', $harness->json($response)['error']);
        $this->assertNull($harness->storage->findCodeByHash(TokenGenerator::hash($code)));
        $this->assertArrayHasKey('access_token', $harness->json($harness->exchange($client, $otherPerson)));
    }

    /**
     * The codes are deleted before the tokens are revoked. In the other order, an exchange completing
     * between the two steps would store its tokens after the revocation and consume its code before the
     * deletion, and survive both.
     */
    public function testAnExchangeBetweenTheTwoStepsCannotSurvive(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $code = $harness->authorizationCode($client);
        $tokens = new class ($harness->storage) extends ThrowingTouchTokens {
            public ?Closure $afterRevoke = null;

            public function revokeTokensBySubject(string $subject, SubjectType $type, DateTimeImmutable $at): int
            {
                $count = parent::revokeTokensBySubject($subject, $type, $at);
                $hook = $this->afterRevoke;
                $this->afterRevoke = null;
                if ($hook !== null) {
                    $hook();
                }

                return $count;
            }
        };
        $exchange = null;
        $tokens->afterRevoke = function () use (&$exchange, $harness, $client, $code): void {
            $exchange = $harness->exchange($client, $code);
        };
        $revoker = new TokenRevoker($tokens, $harness->storage, $harness->clock, $harness->events);

        $revoker->revokeAllForSubject('42');

        $this->assertNotNull($exchange);
        $this->assertSame('invalid_grant', $harness->json($exchange)['error'] ?? null);
        $this->assertSame([], $harness->storage->findActiveTokensBySubject('42', SubjectType::User, $harness->clock->now()));
    }

    public function testRevokingAConnectionDeletesThePendingCodesOfThatPersonAndClient(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $other = $harness->publicClient();
        $first = $harness->json($harness->exchange($client, $harness->authorizationCode($client)));
        $pending = $harness->authorizationCode($client);
        $otherClient = $harness->authorizationCode($other);
        $family = $harness->storage->findTokenByHash(TokenGenerator::hash($first['access_token']))?->familyId;
        $this->assertNotNull($family);

        $this->assertTrue($harness->server->connectionService()->revokeConnection($harness->users->users['42'], $family));

        $this->assertSame('invalid_grant', $harness->json($harness->exchange($client, $pending))['error'] ?? null);
        $this->assertArrayHasKey('access_token', $harness->json($harness->exchange($other, $otherClient)));
    }

    public function testRevokingAClientDeletesItsPendingCodes(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $code = $harness->authorizationCode($client);
        $otherPerson = $harness->authorizationCode($client, [], '43');

        $harness->storage->saveClient($client->withRevokedAt($harness->clock->now()));
        $harness->server->tokenRevoker()->revokeAllForClient($client);

        $this->assertNull($harness->storage->findCodeByHash(TokenGenerator::hash($code)));
        $this->assertNull($harness->storage->findCodeByHash(TokenGenerator::hash($otherPerson)));
    }

    public function testAnExchangedCodeIsKeptSoAReplayStillRevokesWhatItIssued(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $code = $harness->authorizationCode($client);
        $harness->exchange($client, $code);

        $harness->server->tokenRevoker()->revokeAllForSubject('42');

        $kept = $harness->storage->findCodeByHash(TokenGenerator::hash($code));
        $this->assertNotNull($kept?->usedAt);
        $this->assertNotNull($kept->familyId);
    }
}
