<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Connections;

use CakeDC\OAuth\Server\Client\Client;
use DateTimeImmutable;

/**
 * One authorization an owner gave a client: a live token family.
 */
final class Connection
{
    /**
     * @param string $familyId The token family.
     * @param \CakeDC\OAuth\Server\Client\Client $client The client.
     * @param string $resource Canonical resource identifier.
     * @param list<string> $scopes Scopes of the newest token.
     * @param \DateTimeImmutable $connectedAt When the owner approved.
     * @param \DateTimeImmutable|null $lastUsedAt Last use of any of its tokens.
     */
    public function __construct(
        public readonly string $familyId,
        public readonly Client $client,
        public readonly string $resource,
        public readonly array $scopes,
        public readonly DateTimeImmutable $connectedAt,
        public readonly ?DateTimeImmutable $lastUsedAt,
    ) {
    }
}
