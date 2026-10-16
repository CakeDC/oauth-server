<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Grant;

use DateTimeImmutable;

/**
 * What an owner already accepted for a client on a resource.
 */
final class Consent
{
    /**
     * @param string $id Internal UUID.
     * @param string $subject Owner subject.
     * @param string $clientInternalId Client::$id.
     * @param string $resource Canonical resource identifier.
     * @param list<string> $scopes Accepted scopes.
     * @param \DateTimeImmutable $createdAt First consent.
     * @param \DateTimeImmutable $modifiedAt Last change.
     */
    public function __construct(
        public readonly string $id,
        public readonly string $subject,
        public readonly string $clientInternalId,
        public readonly string $resource,
        public readonly array $scopes,
        public readonly DateTimeImmutable $createdAt,
        public readonly DateTimeImmutable $modifiedAt,
    ) {
    }

    /**
     * Whether every scope in $scopes was accepted.
     *
     * @param list<string> $scopes Scopes.
     */
    public function covers(array $scopes): bool
    {
        return array_diff($scopes, $this->scopes) === [];
    }
}
