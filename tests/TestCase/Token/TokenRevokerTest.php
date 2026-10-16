<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Token;

use CakeDC\OAuth\Server\Config\Lifetimes;
use CakeDC\OAuth\Server\Event\TokenRevoked;
use CakeDC\OAuth\Server\Grant\AuthorizationCode;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Storage\InMemory\InMemoryStorage;
use CakeDC\OAuth\Server\Support\Uuid;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\RecordingEventDispatcher;
use CakeDC\OAuth\Server\Testing\FrozenClock;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use CakeDC\OAuth\Server\Token\TokenIssuer;
use CakeDC\OAuth\Server\Token\TokenRevoker;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

class TokenRevokerTest extends TestCase
{
    private InMemoryStorage $storage;

    private RecordingEventDispatcher $events;

    private TokenIssuer $issuer;

    private TokenRevoker $revoker;

    protected function setUp(): void
    {
        $this->storage = new InMemoryStorage();
        $this->events = new RecordingEventDispatcher();
        $clock = new FrozenClock();
        $this->issuer = new TokenIssuer($this->storage, new TokenGenerator(), $clock, $this->events, new Lifetimes());
        $this->revoker = new TokenRevoker($this->storage, $this->storage, $clock, $this->events);
    }

    public function testARefreshTokenTakesItsFamilyAndAnAccessTokenOnlyItself(): void
    {
        $client = Fixtures::client();
        $resource = Fixtures::resources()->defaultResource();
        $first = $this->issuer->issue($client, '42', SubjectType::User, $resource, [], 'family-a', true);
        $second = $this->issuer->issue($client, '42', SubjectType::User, $resource, [], 'family-b', true);

        $this->revoker->revokeForClient($client, $first->accessToken);
        $this->assertNotNull($this->storage->findTokenById($first->access->id)?->revokedAt);
        $this->assertNull($this->storage->findTokenById((string)$first->refresh?->id)?->revokedAt);

        $this->revoker->revokeForClient($client, (string)$second->refreshToken);
        $this->assertNotNull($this->storage->findTokenById($second->access->id)?->revokedAt);
        $this->assertSame('client', $this->events->ofType(TokenRevoked::class)[1]->reason);
        $this->assertSame(2, $this->events->ofType(TokenRevoked::class)[1]->count);
    }

    public function testIgnoresUnknownAndForeignTokens(): void
    {
        $owner = Fixtures::client();
        $other = Fixtures::client();
        $issued = $this->issuer->issue($owner, '42', SubjectType::User, Fixtures::resources()->defaultResource(), [], 'f', false);

        $this->revoker->revokeForClient($other, $issued->accessToken);
        $this->revoker->revokeForClient($other, 'nonsense');

        $this->assertNull($this->storage->findTokenById($issued->access->id)?->revokedAt);
        $this->assertSame([], $this->events->ofType(TokenRevoked::class));
    }

    public function testRevokesEverythingOfASubjectOrClient(): void
    {
        $client = Fixtures::client();
        $resource = Fixtures::resources()->defaultResource();
        $this->issuer->issue($client, '42', SubjectType::User, $resource, [], 'a', true);
        $this->issuer->issue($client, '43', SubjectType::User, $resource, [], 'b', true);

        $this->assertSame(2, $this->revoker->revokeAllForSubject('42'));
        $this->assertSame(2, $this->revoker->revokeAllForClient($client));
        $this->assertSame(['subject', 'client_revoked'], array_map(
            fn(TokenRevoked $e): string => $e->reason,
            $this->events->ofType(TokenRevoked::class),
        ));
    }

    private function code(string $clientInternalId, string $subject = '42'): AuthorizationCode
    {
        $code = new AuthorizationCode(
            id: Uuid::v4(),
            codeHash: TokenGenerator::hash(Uuid::v4()),
            clientInternalId: $clientInternalId,
            subject: $subject,
            redirectUri: 'https://app.example.com/cb',
            resource: Fixtures::MCP,
            scopes: ['content:read'],
            codeChallenge: str_repeat('a', 43),
            expiresAt: new DateTimeImmutable('+60 seconds'),
            createdAt: new DateTimeImmutable(),
        );
        $this->storage->saveCode($code);

        return $code;
    }

    public function testRevokingAPersonDeletesTheirPendingCodesFirst(): void
    {
        $client = Fixtures::client();
        $mine = $this->code($client->id);
        $theirs = $this->code($client->id, '43');
        $robot = $this->code($client->id, 'robot');

        $this->revoker->revokeAllForSubject('42');
        $this->revoker->revokeAllForSubject('robot', SubjectType::Client);

        $this->assertNull($this->storage->findCodeByHash($mine->codeHash));
        $this->assertNotNull($this->storage->findCodeByHash($theirs->codeHash));
        // Codes belong to people: revoking a client identity with the same subject leaves them.
        $this->assertNotNull($this->storage->findCodeByHash($robot->codeHash));
    }

    public function testRevokingAClientDeletesItsPendingCodes(): void
    {
        $client = Fixtures::client();
        $other = Fixtures::client();
        $mine = $this->code($client->id);
        $notMine = $this->code($other->id);

        $this->revoker->revokeAllForClient($client);

        $this->assertNull($this->storage->findCodeByHash($mine->codeHash));
        $this->assertNotNull($this->storage->findCodeByHash($notMine->codeHash));
    }

    public function testAForeignClientsRefreshTokenDoesNothing(): void
    {
        $owner = Fixtures::client();
        $other = Fixtures::client();
        $issued = $this->issuer->issue(
            $owner,
            '42',
            SubjectType::User,
            Fixtures::resources()->defaultResource(),
            [],
            'f',
            true,
        );

        $this->revoker->revokeForClient($other, (string)$issued->refreshToken);

        $this->assertNull($this->storage->findTokenById($issued->access->id)?->revokedAt);
        $this->assertNull($this->storage->findTokenById((string)$issued->refresh?->id)?->revokedAt);
        $this->assertSame([], $this->events->ofType(TokenRevoked::class));
    }

    public function testAnAlreadyRevokedAccessTokenSendsNoEvent(): void
    {
        $client = Fixtures::client();
        $issued = $this->issuer->issue(
            $client,
            '42',
            SubjectType::User,
            Fixtures::resources()->defaultResource(),
            [],
            'f',
            false,
        );

        $this->revoker->revokeForClient($client, $issued->accessToken);
        $this->revoker->revokeForClient($client, $issued->accessToken);

        $this->assertCount(1, $this->events->ofType(TokenRevoked::class));
    }

    public function testRevokesAListOfTokensAndCountsOnlyNewRevocations(): void
    {
        $client = Fixtures::client();
        $issued = $this->issuer->issue(
            $client,
            '42',
            SubjectType::User,
            Fixtures::resources()->defaultResource(),
            [],
            'f',
            true,
        );
        $this->storage->revokeToken($issued->access->id, new DateTimeImmutable());

        $count = $this->revoker->revokeTokens([$issued->access, $issued->refresh], 'grace');

        $this->assertSame(1, $count);
        $this->assertSame(1, $this->events->ofType(TokenRevoked::class)[0]->count);
        $this->assertSame(0, $this->revoker->revokeTokens([$issued->access, $issued->refresh], 'grace'));
        $this->assertCount(1, $this->events->ofType(TokenRevoked::class));
    }
}
