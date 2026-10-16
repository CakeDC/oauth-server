<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Storage\Pdo;

use CakeDC\OAuth\Server\Client\ClientType;
use CakeDC\OAuth\Server\Grant\Consent;
use CakeDC\OAuth\Server\Storage\Pdo\PdoStorage;
use CakeDC\OAuth\Server\Support\Uuid;
use CakeDC\OAuth\Server\Test\Support\HookedPdo;
use CakeDC\OAuth\Server\Token\TokenType;
use PDO;

/**
 * Races a sequential contract cannot show: another request commits between the storage's read and its
 * write. Used by the PDO contract tests of every driver, which provide connect().
 */
trait PdoConcurrencyTestsTrait
{
    /**
     * A connection to empty tables with the default prefix.
     */
    abstract protected function connect(): HookedPdo;

    /**
     * Two first consents for the same person, client and resource (a double click on "Allow"): the one
     * that loses the race on the unique key updates the winner's row instead of failing.
     */
    public function testAConcurrentFirstConsentUpdatesInsteadOfFailing(): void
    {
        $pdo = $this->connect();
        $storage = new PdoStorage($pdo);
        $client = $this->makeClient();
        $storage->saveClient($client);
        $resource = 'https://example.com/mcp';
        $winner = new Consent(Uuid::v4(), '42', $client->id, $resource, ['content:read'], $this->at(), $this->at());
        $pdo->beforePrepare(
            'INSERT INTO oauth_consents',
            fn(PDO $pdo) => (new PdoStorage($pdo))->saveConsent($winner),
        );

        $storage->saveConsent(
            new Consent(Uuid::v4(), '42', $client->id, $resource, ['content:write'], $this->at(5), $this->at(5)),
        );

        $found = $storage->findConsent('42', $client->id, $resource);
        $this->assertNotNull($found);
        $this->assertSame($winner->id, $found->id);
        $this->assertSame(['content:write'], $found->scopes);
        $this->assertEquals($this->at(), $found->createdAt);
        $this->assertEquals($this->at(5), $found->modifiedAt);
        $this->assertCount(1, $storage->findConsentsBySubject('42'));
    }

    /**
     * A client selected for pruning and then used by a request (its last use recorded) is kept.
     */
    public function testPruneKeepsAClientTouchedAfterItWasSelected(): void
    {
        $day = 86400;
        $pdo = $this->connect();
        $storage = new PdoStorage($pdo);
        $used = $this->makeClient(ClientType::Dynamic);
        $unused = $this->makeClient(ClientType::MetadataDocument, 'https://old.example/client.json');
        $storage->saveClient($used);
        $storage->saveClient($unused);
        $code = $this->makeCode($used, 20 * $day);
        $storage->saveCode($code);
        $storage->saveConsent(
            new Consent(Uuid::v4(), '42', $used->id, 'https://example.com/mcp', ['a'], $this->at(), $this->at()),
        );
        $pdo->beforeTransaction(fn(PDO $pdo) => (new PdoStorage($pdo))->touchClient($used->id, $this->at(10 * $day)));

        $result = $storage->prune($this->at(10 * $day), 2 * $day, $day);

        $this->assertSame(1, $result->clients);
        $this->assertSame(0, $result->codes);
        $this->assertNotNull($storage->findClientById($used->id));
        $this->assertNotNull($storage->findCodeByHash($code->codeHash));
        $this->assertNotNull($storage->findConsent('42', $used->id, 'https://example.com/mcp'));
        $this->assertNull($storage->findClientById($unused->id));
    }

    /**
     * A client selected for pruning that gets a live token before its rows are deleted is kept, with
     * the token.
     */
    public function testPruneKeepsAClientThatGotALiveTokenAfterItWasSelected(): void
    {
        $day = 86400;
        $pdo = $this->connect();
        $storage = new PdoStorage($pdo);
        $client = $this->makeClient(ClientType::Dynamic);
        $storage->saveClient($client);
        $old = $this->makeToken($client, expiresIn: 60);
        $storage->saveToken($old);
        $fresh = $this->makeToken($client, TokenType::Refresh, expiresIn: 30 * $day, createdAt: 10 * $day);
        $pdo->beforeTransaction(fn(PDO $pdo) => (new PdoStorage($pdo))->saveToken($fresh));

        $result = $storage->prune($this->at(10 * $day), 2 * $day, $day);

        $this->assertSame(0, $result->clients);
        $this->assertSame(1, $result->tokens);
        $this->assertNotNull($storage->findClientById($client->id));
        $this->assertNotNull($storage->findTokenById($fresh->id));
        $this->assertNull($storage->findTokenById($old->id));
    }
}
