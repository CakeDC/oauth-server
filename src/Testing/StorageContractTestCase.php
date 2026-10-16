<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Testing;

use CakeDC\OAuth\Server\Client\ApplicationType;
use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Client\ClientAuthMethod;
use CakeDC\OAuth\Server\Client\ClientType;
use CakeDC\OAuth\Server\Grant\AuthorizationCode;
use CakeDC\OAuth\Server\Grant\Consent;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Storage\StorageInterface;
use CakeDC\OAuth\Server\Support\Time;
use CakeDC\OAuth\Server\Support\Uuid;
use CakeDC\OAuth\Server\Token\Token;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use CakeDC\OAuth\Server\Token\TokenType;
use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\TestCase;

/**
 * The behaviour every storage implementation must have. Extend it and implement createStorage().
 */
abstract class StorageContractTestCase extends TestCase
{
    /**
     * A storage with no rows.
     */
    abstract protected function createStorage(): StorageInterface;

    /**
     * 2026-01-01 00:00:00 UTC plus $seconds.
     */
    protected function at(int $seconds = 0): DateTimeImmutable
    {
        return Time::plus(new DateTimeImmutable('2026-01-01 00:00:00', new DateTimeZone('UTC')), $seconds);
    }

    /**
     * A client with every field set.
     */
    protected function makeClient(
        ClientType $type = ClientType::Registered,
        ?string $clientId = null,
        int $createdAt = 0,
    ): Client {
        return new Client(
            id: Uuid::v4(),
            clientId: $clientId ?? bin2hex(random_bytes(16)),
            type: $type,
            applicationType: ApplicationType::Native,
            name: 'Test client',
            redirectUris: ['https://app.example.com/cb', 'http://127.0.0.1/cb'],
            grantTypes: ['authorization_code', 'refresh_token'],
            authMethod: ClientAuthMethod::SecretBasic,
            createdAt: $this->at($createdAt),
            secretHash: TokenGenerator::hash('secret'),
            scopes: ['content:read', 'content:write'],
            clientUri: 'https://app.example.com',
            logoUri: 'https://app.example.com/logo.png',
            allowIntrospection: true,
            metadata: ['client_name' => 'Test client', 'nested' => ['a' => 1]],
            metadataFetchedAt: $this->at(10),
            metadataExpiresAt: $this->at(310),
            lastUsedAt: null,
            revokedAt: null,
        );
    }

    /**
     * An unused code of $client.
     */
    protected function makeCode(Client $client, int $expiresIn = 60): AuthorizationCode
    {
        return new AuthorizationCode(
            id: Uuid::v4(),
            codeHash: TokenGenerator::hash(Uuid::v4()),
            clientInternalId: $client->id,
            subject: '42',
            redirectUri: 'https://app.example.com/cb',
            resource: 'https://example.com/mcp',
            scopes: ['content:read', 'offline_access'],
            codeChallenge: str_repeat('a', 43),
            expiresAt: $this->at($expiresIn),
            createdAt: $this->at(),
        );
    }

    /**
     * A token of $client for subject 42.
     */
    protected function makeToken(
        ?Client $client,
        TokenType $type = TokenType::Access,
        ?string $familyId = null,
        ?int $expiresIn = 3600,
        int $createdAt = 0,
        string $subject = '42',
        SubjectType $subjectType = SubjectType::User,
    ): Token {
        return new Token(
            id: Uuid::v4(),
            tokenHash: TokenGenerator::hash(Uuid::v4()),
            type: $type,
            familyId: $familyId ?? Uuid::v4(),
            clientInternalId: $client?->id,
            subject: $subject,
            subjectType: $subjectType,
            resource: 'https://example.com/mcp',
            scopes: ['content:read'],
            createdAt: $this->at($createdAt),
            expiresAt: $expiresIn === null ? null : $this->at($createdAt + $expiresIn),
            name: $client === null ? 'CI token' : null,
            parentId: null,
        );
    }

    /**
     * Clients keep every field.
     */
    public function testSavesAndFindsClients(): void
    {
        $storage = $this->createStorage();
        $client = $this->makeClient();
        $storage->saveClient($client);

        $this->assertEquals($client, $storage->findClientById($client->id));
        $this->assertEquals($client, $storage->findClientByClientId($client->clientId));
        $this->assertNull($storage->findClientByClientId('unknown'));
        $this->assertNull($storage->findClientById(Uuid::v4()));
    }

    /**
     * Metadata document client ids are long URLs.
     */
    public function testFindsClientsByLongClientIds(): void
    {
        $storage = $this->createStorage();
        $clientId = 'https://example.com/' . str_repeat('very-long-path/', 60) . 'client.json';
        $storage->saveClient($this->makeClient(ClientType::MetadataDocument, $clientId));

        $this->assertSame($clientId, $storage->findClientByClientId($clientId)?->clientId);
    }

    /**
     * Saving a client with a known id updates it.
     */
    public function testSavingAClientAgainUpdatesIt(): void
    {
        $storage = $this->createStorage();
        $client = $this->makeClient();
        $storage->saveClient($client);
        $storage->saveClient($client->withRevokedAt($this->at(100)));

        $found = $storage->findClientById($client->id);
        $this->assertNotNull($found);
        $this->assertTrue($found->isRevoked());
        $this->assertEquals($this->at(100), $found->revokedAt);
        $this->assertCount(1, $storage->findClients());
    }

    /**
     * A stale, un-revoked copy of a client cannot undo a revocation.
     */
    public function testRevocationIsSticky(): void
    {
        $storage = $this->createStorage();
        $client = $this->makeClient();
        $storage->saveClient($client);
        $storage->saveClient($client->withRevokedAt($this->at(100)));
        $storage->saveClient($client);
        $storage->saveClient($client->withRevokedAt($this->at(200)));

        $found = $storage->findClientById($client->id);
        $this->assertNotNull($found);
        $this->assertTrue($found->isRevoked());
        $this->assertEquals($this->at(100), $found->revokedAt);
    }

    /**
     * Clients can be listed by type.
     */
    public function testFindsClientsByType(): void
    {
        $storage = $this->createStorage();
        $storage->saveClient($this->makeClient(ClientType::Registered));
        $storage->saveClient($this->makeClient(ClientType::Dynamic, null, 10));
        $storage->saveClient($this->makeClient(ClientType::Dynamic, null, 5));

        $this->assertCount(3, $storage->findClients());
        $dynamic = $storage->findClients(ClientType::Dynamic);
        $this->assertCount(2, $dynamic);
        $this->assertEquals($this->at(5), $dynamic[0]->createdAt);
    }

    /**
     * Touching a client records its last use.
     */
    public function testTouchesClients(): void
    {
        $storage = $this->createStorage();
        $client = $this->makeClient();
        $storage->saveClient($client);
        $storage->touchClient($client->id, $this->at(50));

        $this->assertEquals($this->at(50), $storage->findClientById($client->id)?->lastUsedAt);
    }

    /**
     * A code can be consumed once.
     */
    public function testCodesAreConsumedOnce(): void
    {
        $storage = $this->createStorage();
        $client = $this->makeClient();
        $storage->saveClient($client);
        $code = $this->makeCode($client);
        $storage->saveCode($code);

        $this->assertEquals($code, $storage->findCodeByHash($code->codeHash));
        $this->assertTrue($storage->consumeCode($code->id, $this->at(5), '00000000-0000-4000-8000-0000000000f1'));
        $this->assertFalse($storage->consumeCode($code->id, $this->at(6), '00000000-0000-4000-8000-0000000000f2'));

        $used = $storage->findCodeByHash($code->codeHash);
        $this->assertEquals($this->at(5), $used?->usedAt);
        $this->assertSame('00000000-0000-4000-8000-0000000000f1', $used?->familyId);
        $this->assertNull($storage->findCodeByHash('unknown'));
    }

    /**
     * Tokens keep every field.
     */
    public function testTokensRoundTrip(): void
    {
        $storage = $this->createStorage();
        $client = $this->makeClient();
        $storage->saveClient($client);
        $token = new Token(
            id: Uuid::v4(),
            tokenHash: TokenGenerator::hash('t'),
            type: TokenType::Refresh,
            familyId: Uuid::v4(),
            clientInternalId: $client->id,
            subject: 'user-7',
            subjectType: SubjectType::User,
            resource: 'https://example.com/mcp',
            scopes: ['content:read', 'content:write'],
            createdAt: $this->at(),
            expiresAt: $this->at(100),
            name: null,
            parentId: Uuid::v4(),
            familyStartedAt: $this->at(-50),
        );
        $storage->saveToken($token);
        $personal = $this->makeToken(null, TokenType::Personal, null, null);
        $storage->saveToken($personal);

        $this->assertEquals($token, $storage->findTokenByHash($token->tokenHash));
        $this->assertEquals($token, $storage->findTokenById($token->id));
        $this->assertEquals($personal, $storage->findTokenById($personal->id));
        $this->assertNull($storage->findTokenByHash('unknown'));
    }

    /**
     * A refresh token can be marked used once.
     */
    public function testRefreshTokensAreMarkedUsedOnce(): void
    {
        $storage = $this->createStorage();
        $client = $this->makeClient();
        $storage->saveClient($client);
        $token = $this->makeToken($client, TokenType::Refresh);
        $storage->saveToken($token);

        $this->assertTrue($storage->markTokenUsed($token->id, $this->at(3)));
        $this->assertFalse($storage->markTokenUsed($token->id, $this->at(4)));
        $this->assertEquals($this->at(3), $storage->findTokenById($token->id)?->usedAt);
    }

    /**
     * A revoked token cannot be marked used, so a revocation beats a rotation in flight.
     */
    public function testRevokedTokensCannotBeMarkedUsed(): void
    {
        $storage = $this->createStorage();
        $client = $this->makeClient();
        $storage->saveClient($client);
        $token = $this->makeToken($client, TokenType::Refresh);
        $storage->saveToken($token);
        $storage->revokeToken($token->id, $this->at(1));

        $this->assertFalse($storage->markTokenUsed($token->id, $this->at(2)));
        $this->assertNull($storage->findTokenById($token->id)?->usedAt);
    }

    /**
     * Revocation counts only tokens that were still live.
     */
    public function testRevokesTokensAndFamilies(): void
    {
        $storage = $this->createStorage();
        $client = $this->makeClient();
        $storage->saveClient($client);
        $family = Uuid::v4();
        $a = $this->makeToken($client, TokenType::Access, $family);
        $b = $this->makeToken($client, TokenType::Refresh, $family);
        $other = $this->makeToken($client);
        foreach ([$a, $b, $other] as $token) {
            $storage->saveToken($token);
        }

        $storage->revokeToken($a->id, $this->at(1));
        $this->assertSame(1, $storage->revokeTokenFamily($family, $this->at(2)));
        $this->assertSame(0, $storage->revokeTokenFamily($family, $this->at(3)));
        $this->assertEquals($this->at(1), $storage->findTokenById($a->id)?->revokedAt);
        $this->assertEquals($this->at(2), $storage->findTokenById($b->id)?->revokedAt);
        $this->assertNull($storage->findTokenById($other->id)?->revokedAt);
    }

    /**
     * Revocation by subject and by client.
     */
    public function testRevokesBySubjectAndClient(): void
    {
        $storage = $this->createStorage();
        $first = $this->makeClient();
        $second = $this->makeClient();
        $storage->saveClient($first);
        $storage->saveClient($second);
        $storage->saveToken($this->makeToken($first));
        $secondUser = $this->makeToken($second);
        $storage->saveToken($secondUser);
        $storage->saveToken($this->makeToken($second, subject: '43'));
        $storage->saveToken($this->makeToken($second, subject: '42', subjectType: SubjectType::Client));

        $this->assertSame(2, $storage->revokeTokensBySubject('42', SubjectType::User, $this->at(1)));
        $this->assertSame(2, $storage->revokeTokensByClient($second->id, $this->at(2)));
        $this->assertSame(0, $storage->revokeTokensByClient($second->id, $this->at(3)));
        $this->assertEquals($this->at(1), $storage->findTokenById($secondUser->id)?->revokedAt);
    }

    /**
     * Active tokens exclude revoked, expired and foreign ones.
     */
    public function testFindsActiveTokensOfASubject(): void
    {
        $storage = $this->createStorage();
        $client = $this->makeClient();
        $storage->saveClient($client);
        $live = $this->makeToken($client, createdAt: 5);
        $older = $this->makeToken($client, TokenType::Refresh, createdAt: 1);
        $personal = $this->makeToken(null, TokenType::Personal, expiresIn: null, createdAt: 9);
        $expired = $this->makeToken($client, expiresIn: 10);
        $revoked = $this->makeToken($client);
        $foreign = $this->makeToken($client, subject: '43');
        foreach ([$live, $older, $personal, $expired, $revoked, $foreign] as $token) {
            $storage->saveToken($token);
        }
        $storage->revokeToken($revoked->id, $this->at(1));

        $active = $storage->findActiveTokensBySubject('42', SubjectType::User, $this->at(60));
        $this->assertSame([$older->id, $live->id, $personal->id], array_map(fn(Token $t) => $t->id, $active));
        $this->assertSame([], $storage->findActiveTokensBySubject('42', SubjectType::Client, $this->at(60)));
    }

    /**
     * Family members come oldest first.
     */
    public function testFindsTokensByFamily(): void
    {
        $storage = $this->createStorage();
        $client = $this->makeClient();
        $storage->saveClient($client);
        $family = Uuid::v4();
        $second = $this->makeToken($client, TokenType::Access, $family, createdAt: 20);
        $first = $this->makeToken($client, TokenType::Refresh, $family, createdAt: 10);
        $storage->saveToken($second);
        $storage->saveToken($first);
        $storage->saveToken($this->makeToken($client));

        $found = $storage->findTokensByFamily($family);
        $this->assertSame([$first->id, $second->id], array_map(fn(Token $t) => $t->id, $found));
    }

    /**
     * Touching a token records its last use.
     */
    public function testTouchesTokens(): void
    {
        $storage = $this->createStorage();
        $client = $this->makeClient();
        $storage->saveClient($client);
        $token = $this->makeToken($client);
        $storage->saveToken($token);
        $storage->touchToken($token->id, $this->at(30));

        $this->assertEquals($this->at(30), $storage->findTokenById($token->id)?->lastUsedAt);
    }

    /**
     * One consent per subject, client and resource.
     */
    public function testConsentIsUpsertedPerSubjectClientAndResource(): void
    {
        $storage = $this->createStorage();
        $client = $this->makeClient();
        $storage->saveClient($client);
        $first = new Consent(Uuid::v4(), '42', $client->id, 'https://example.com/mcp', ['a'], $this->at(), $this->at());
        $storage->saveConsent($first);
        $storage->saveConsent(
            new Consent(
                Uuid::v4(),
                '42',
                $client->id,
                'https://example.com/mcp',
                ['a', 'b'],
                $this->at(9),
                $this->at(9),
            ),
        );
        $storage->saveConsent(
            new Consent(Uuid::v4(), '42', $client->id, 'https://example.com/api', ['x'], $this->at(), $this->at()),
        );

        $found = $storage->findConsent('42', $client->id, 'https://example.com/mcp');
        $this->assertNotNull($found);
        $this->assertSame($first->id, $found->id);
        $this->assertSame(['a', 'b'], $found->scopes);
        $this->assertEquals($this->at(), $found->createdAt);
        $this->assertEquals($this->at(9), $found->modifiedAt);
        $this->assertSame(['x'], $storage->findConsent('42', $client->id, 'https://example.com/api')?->scopes);
        $this->assertNull($storage->findConsent('43', $client->id, 'https://example.com/mcp'));
    }

    /**
     * Consents can be deleted.
     */
    public function testDeletesConsents(): void
    {
        $storage = $this->createStorage();
        $client = $this->makeClient();
        $storage->saveClient($client);
        $storage->saveConsent(
            new Consent(Uuid::v4(), '42', $client->id, 'https://example.com/mcp', ['a'], $this->at(), $this->at()),
        );
        $storage->deleteConsent('42', $client->id, 'https://example.com/mcp');

        $this->assertNull($storage->findConsent('42', $client->id, 'https://example.com/mcp'));
    }

    /**
     * Pruning deletes expired codes and old dead tokens only.
     */
    public function testPruneRemovesExpiredCodesAndOldTokens(): void
    {
        $storage = $this->createStorage();
        $client = $this->makeClient();
        $storage->saveClient($client);
        $expiredCode = $this->makeCode($client, 60);
        $liveCode = $this->makeCode($client, 5 * 86400);
        $storage->saveCode($expiredCode);
        $storage->saveCode($liveCode);
        $oldExpired = $this->makeToken($client, expiresIn: 60);
        $recentExpired = $this->makeToken($client, expiresIn: 3600, createdAt: 3 * 86400);
        $oldRevoked = $this->makeToken($client, expiresIn: null);
        $live = $this->makeToken($client, expiresIn: null);
        $recentRevoked = $this->makeToken($client, expiresIn: null);
        foreach ([$oldExpired, $recentExpired, $oldRevoked, $recentRevoked, $live] as $token) {
            $storage->saveToken($token);
        }
        $storage->revokeToken($oldRevoked->id, $this->at(60));
        $storage->revokeToken($recentRevoked->id, $this->at(3 * 86400));

        $result = $storage->prune($this->at(4 * 86400), 2 * 86400, 86400);

        $this->assertSame(1, $result->codes);
        $this->assertSame(2, $result->tokens);
        $this->assertSame(0, $result->clients);
        $this->assertNull($storage->findCodeByHash($expiredCode->codeHash));
        $this->assertNotNull($storage->findCodeByHash($liveCode->codeHash));
        $this->assertNull($storage->findTokenById($oldExpired->id));
        $this->assertNull($storage->findTokenById($oldRevoked->id));
        $this->assertNotNull($storage->findTokenById($recentExpired->id));
        $this->assertNotNull($storage->findTokenById($recentRevoked->id));
        $this->assertNotNull($storage->findTokenById($live->id));
    }

    /**
     * Pruning deletes unused dynamic and metadata document clients with their rows.
     */
    public function testPruneRemovesUnusedDynamicClientsOnly(): void
    {
        $day = 86400;
        $storage = $this->createStorage();
        $registered = $this->makeClient(ClientType::Registered);
        $abandoned = $this->makeClient(ClientType::Dynamic);
        $touchedRecently = $this->makeClient(ClientType::Dynamic);
        $touchedLongAgo = $this->makeClient(ClientType::Dynamic);
        $oldMetadata = $this->makeClient(ClientType::MetadataDocument, 'https://old.example/client.json');
        $inUse = $this->makeClient(ClientType::Dynamic);
        $recent = $this->makeClient(ClientType::MetadataDocument, 'https://new.example/client.json', 9 * $day + 43200);
        foreach ([$registered, $abandoned, $touchedRecently, $touchedLongAgo, $oldMetadata, $inUse, $recent] as $c) {
            $storage->saveClient($c);
        }
        $storage->touchClient($touchedRecently->id, $this->at(9 * $day));
        $storage->touchClient($touchedLongAgo->id, $this->at($day));
        $storage->saveConsent(
            new Consent(Uuid::v4(), '42', $abandoned->id, 'https://example.com/mcp', ['a'], $this->at(), $this->at()),
        );
        $expiredCode = $this->makeCode($abandoned, 60);
        $liveCode = $this->makeCode($abandoned, 20 * $day);
        $storage->saveCode($expiredCode);
        $storage->saveCode($liveCode);
        $revokedRecently = $this->makeToken($abandoned, expiresIn: null);
        $expiredRecently = $this->makeToken($abandoned, expiresIn: 3600, createdAt: 9 * $day);
        $storage->saveToken($revokedRecently);
        $storage->saveToken($expiredRecently);
        $storage->revokeToken($revokedRecently->id, $this->at(9 * $day + 43200));
        $liveToken = $this->makeToken($inUse, TokenType::Refresh, expiresIn: 30 * $day);
        $storage->saveToken($liveToken);

        $result = $storage->prune($this->at(10 * $day), 2 * $day, $day);

        $this->assertSame(2, $result->codes);
        $this->assertSame(2, $result->tokens);
        $this->assertSame(3, $result->clients);
        $this->assertNull($storage->findClientById($abandoned->id));
        $this->assertNull($storage->findClientById($touchedLongAgo->id));
        $this->assertNull($storage->findClientById($oldMetadata->id));
        $this->assertNull($storage->findCodeByHash($liveCode->codeHash));
        $this->assertNull($storage->findCodeByHash($expiredCode->codeHash));
        $this->assertNull($storage->findTokenById($revokedRecently->id));
        $this->assertNull($storage->findTokenById($expiredRecently->id));
        $this->assertNull($storage->findConsent('42', $abandoned->id, 'https://example.com/mcp'));
        $this->assertNotNull($storage->findClientById($registered->id));
        $this->assertNotNull($storage->findClientById($touchedRecently->id));
        $this->assertNotNull($storage->findClientById($inUse->id));
        $this->assertNotNull($storage->findClientById($recent->id));
        $this->assertNotNull($storage->findTokenById($liveToken->id));
    }

    /**
     * Subjects are compared case-sensitively.
     */
    public function testSubjectsAreCaseSensitive(): void
    {
        $storage = $this->createStorage();
        $client = $this->makeClient();
        $storage->saveClient($client);
        $token = $this->makeToken($client, subject: 'Alice');
        $storage->saveToken($token);
        $storage->saveConsent(
            new Consent(Uuid::v4(), 'Alice', $client->id, 'https://example.com/mcp', ['a'], $this->at(), $this->at()),
        );

        $this->assertSame([], $storage->findActiveTokensBySubject('alice', SubjectType::User, $this->at(1)));
        $this->assertSame(0, $storage->revokeTokensBySubject('alice', SubjectType::User, $this->at(1)));
        $this->assertNull($storage->findConsent('alice', $client->id, 'https://example.com/mcp'));
        $storage->deleteConsent('alice', $client->id, 'https://example.com/mcp');
        $this->assertNotNull($storage->findConsent('Alice', $client->id, 'https://example.com/mcp'));
        $this->assertCount(1, $storage->findActiveTokensBySubject('Alice', SubjectType::User, $this->at(1)));
        $this->assertNull($storage->findTokenById($token->id)?->revokedAt);
    }

    /**
     * Malformed and unknown ids never throw.
     */
    public function testMalformedAndUnknownIdsAreHandled(): void
    {
        $storage = $this->createStorage();

        foreach (['not-a-uuid', Uuid::v4()] as $id) {
            $this->assertNull($storage->findClientById($id));
            $this->assertNull($storage->findTokenById($id));
            $this->assertFalse($storage->consumeCode($id, $this->at(1), Uuid::v4()));
            $this->assertFalse($storage->markTokenUsed($id, $this->at(1)));
            $this->assertSame(0, $storage->revokeTokenFamily($id, $this->at(1)));
            $this->assertSame(0, $storage->revokeTokensByClient($id, $this->at(1)));
            $this->assertSame([], $storage->findTokensByFamily($id));
            $this->assertNull($storage->findConsent('42', $id, 'https://example.com/mcp'));
            $storage->revokeToken($id, $this->at(1));
            $storage->touchToken($id, $this->at(1));
            $storage->touchClient($id, $this->at(1));
            $storage->deleteConsent('42', $id, 'https://example.com/mcp');
        }
    }
}
