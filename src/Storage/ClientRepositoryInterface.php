<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Storage;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Client\ClientType;
use DateTimeImmutable;

/**
 * Stores clients.
 */
interface ClientRepositoryInterface
{
    /**
     * The client with this public `client_id`, revoked or not.
     */
    public function findClientByClientId(string $clientId): ?Client;

    /**
     * The client with this internal id.
     */
    public function findClientById(string $id): ?Client;

    /**
     * Inserts the client, or updates the stored one with the same internal id.
     */
    public function saveClient(Client $client): void;

    /**
     * Records the last use of a client.
     */
    public function touchClient(string $id, DateTimeImmutable $at): void;

    /**
     * All clients, or those of one type, oldest first.
     *
     * @return list<\CakeDC\OAuth\Server\Client\Client>
     */
    public function findClients(?ClientType $type = null): array;
}
