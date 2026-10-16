<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Support;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Client\ClientType;
use CakeDC\OAuth\Server\Storage\ClientRepositoryInterface;
use CakeDC\OAuth\Server\Storage\InMemory\InMemoryStorage;
use DateTimeImmutable;
use RuntimeException;

/**
 * A client repository whose saves can fail, optionally after another process "won" a first-fetch race.
 */
class FlakyClientRepository implements ClientRepositoryInterface
{
    public bool $failSave = false;

    /**
     * Stored by "another process" at the moment of the first save attempt (which then fails).
     */
    public ?Client $raceWinner = null;

    private bool $raced = false;

    public function __construct(public readonly InMemoryStorage $inner = new InMemoryStorage())
    {
    }

    public function findClientByClientId(string $clientId): ?Client
    {
        return $this->inner->findClientByClientId($clientId);
    }

    public function findClientById(string $id): ?Client
    {
        return $this->inner->findClientById($id);
    }

    public function saveClient(Client $client): void
    {
        if ($this->raceWinner !== null && !$this->raced) {
            $this->raced = true;
            $this->inner->saveClient($this->raceWinner);

            throw new RuntimeException('duplicate client_id');
        }
        if ($this->failSave) {
            throw new RuntimeException('disk full');
        }
        $this->inner->saveClient($client);
    }

    public function touchClient(string $id, DateTimeImmutable $at): void
    {
        $this->inner->touchClient($id, $at);
    }

    public function findClients(?ClientType $type = null): array
    {
        return $this->inner->findClients($type);
    }
}
