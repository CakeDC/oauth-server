<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Connections;

use CakeDC\OAuth\Server\Config\Lifetimes;
use CakeDC\OAuth\Server\Connections\ConnectionService;
use CakeDC\OAuth\Server\Event\NullEventDispatcher;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Storage\InMemory\InMemoryStorage;
use CakeDC\OAuth\Server\Storage\Pdo\PdoStorage;
use CakeDC\OAuth\Server\Storage\StorageInterface;
use CakeDC\OAuth\Server\Support\Time;
use CakeDC\OAuth\Server\Test\Support\FakeUsers;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Testing\FrozenClock;
use CakeDC\OAuth\Server\Token\Token;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use CakeDC\OAuth\Server\Token\TokenIssuer;
use CakeDC\OAuth\Server\Token\TokenRevoker;
use CakeDC\OAuth\Server\Token\TokenType;
use Closure;
use PDO;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * A refresh keeps the grant on the refresh token and may narrow the access token, so the two live tokens
 * of a connection can carry different scopes. The connections page shows the grant (the refresh token's
 * scopes) whatever order the storage returns them in; an access token alone speaks for itself.
 */
class ConnectionScopesTest extends TestCase
{
    /**
     * @return array<string, array{\Closure(): \CakeDC\OAuth\Server\Storage\StorageInterface}>
     */
    public static function storages(): array
    {
        return [
            'InMemoryStorage' => [fn(): StorageInterface => new InMemoryStorage()],
            'PdoStorage (SQLite)' => [function (): StorageInterface {
                $pdo = new PDO('sqlite::memory:');
                PdoStorage::createTables($pdo);

                return new PdoStorage($pdo);
            }],
        ];
    }

    /**
     * @param \Closure(): \CakeDC\OAuth\Server\Storage\StorageInterface $storage
     */
    #[DataProvider('storages')]
    public function testTheConnectionShowsTheGrantOfItsRefreshToken(Closure $storage): void
    {
        $storage = $storage();
        $clock = new FrozenClock();
        $client = Fixtures::client();
        $storage->saveClient($client);
        $family = 'f0000000-0000-4000-8000-000000000000';
        // Same second, and the access token sorts last in both storages (inserted last, larger id).
        $storage->saveToken($this->token('00000000-0000-4000-8000-000000000001', TokenType::Refresh, $client->id, $family, ['content:read', 'content:write'], $clock));
        $storage->saveToken($this->token('ffffffff-0000-4000-8000-000000000002', TokenType::Access, $client->id, $family, ['content:read'], $clock));

        $connections = $this->service($storage, $clock)->connections((new FakeUsers())->users['42']);

        $this->assertCount(1, $connections);
        $this->assertSame(['content:read', 'content:write'], $connections[0]->scopes);
    }

    /**
     * @param \Closure(): \CakeDC\OAuth\Server\Storage\StorageInterface $storage
     */
    #[DataProvider('storages')]
    public function testAConnectionWithoutARefreshTokenShowsItsAccessToken(Closure $storage): void
    {
        $storage = $storage();
        $clock = new FrozenClock();
        $client = Fixtures::client();
        $storage->saveClient($client);
        $storage->saveToken($this->token('00000000-0000-4000-8000-000000000003', TokenType::Access, $client->id, 'f1', ['content:write'], $clock));

        $connections = $this->service($storage, $clock)->connections((new FakeUsers())->users['42']);

        $this->assertSame(['content:write'], $connections[0]->scopes ?? null);
    }

    /**
     * A rotated (used) refresh token is not the grant any more: the newest one that was not used is.
     *
     * @param \Closure(): \CakeDC\OAuth\Server\Storage\StorageInterface $storage
     */
    #[DataProvider('storages')]
    public function testTheNewestUnusedRefreshTokenIsTheGrant(Closure $storage): void
    {
        $storage = $storage();
        $clock = new FrozenClock();
        $client = Fixtures::client();
        $storage->saveClient($client);
        $family = 'f2';
        $old = $this->token('00000000-0000-4000-8000-000000000004', TokenType::Refresh, $client->id, $family, ['content:read'], $clock);
        $storage->saveToken($old);
        $storage->markTokenUsed($old->id, $clock->now());
        $clock->advance(10);
        $storage->saveToken($this->token('00000000-0000-4000-8000-000000000005', TokenType::Refresh, $client->id, $family, ['content:read', 'content:publish'], $clock));
        $storage->saveToken($this->token('ffffffff-0000-4000-8000-000000000006', TokenType::Access, $client->id, $family, ['content:read'], $clock));

        $connections = $this->service($storage, $clock)->connections((new FakeUsers())->users['42']);

        $this->assertSame(['content:read', 'content:publish'], $connections[0]->scopes ?? null);
    }

    /**
     * @param list<string> $scopes
     */
    private function token(string $id, TokenType $type, string $clientId, string $family, array $scopes, FrozenClock $clock): Token
    {
        $now = $clock->now();

        return new Token(
            id: $id,
            tokenHash: hash('sha256', $id),
            type: $type,
            familyId: $family,
            clientInternalId: $clientId,
            subject: '42',
            subjectType: SubjectType::User,
            resource: Fixtures::MCP,
            scopes: $scopes,
            createdAt: $now,
            expiresAt: Time::plus($now, $type === TokenType::Refresh ? 86400 : 3600),
            familyStartedAt: $now,
        );
    }

    private function service(StorageInterface $storage, FrozenClock $clock): ConnectionService
    {
        $events = new NullEventDispatcher();

        return new ConnectionService(
            $storage,
            $storage,
            $storage,
            $storage,
            new TokenIssuer($storage, new TokenGenerator(), $clock, $events, new Lifetimes()),
            new TokenRevoker($storage, $storage, $clock, $events),
            Fixtures::resources(),
            new FakeUsers(),
            $clock,
        );
    }
}
