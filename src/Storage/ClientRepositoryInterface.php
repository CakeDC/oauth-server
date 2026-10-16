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
     *
     * Revocation is sticky: an update never clears a stored `revokedAt`. It may set one, but saving a client
     * whose `revokedAt` is null keeps the stored value, so a stale copy cannot undo a revocation.
     *
     * The `client_id` is unique: saving a client whose `client_id` belongs to another stored row (another
     * internal id) throws, as a unique key would, and leaves both rows unchanged. Two concurrent first
     * fetches of a metadata document rely on it: one insert wins, the other reads the winner back.
     *
     * @throws \RuntimeException When another row already has this `client_id`.
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
