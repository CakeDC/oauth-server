<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Grant;

use DateTimeImmutable;

/**
 * A one-time authorization code, stored by hash.
 */
final class AuthorizationCode
{
    /**
     * @param string $id Internal UUID.
     * @param string $codeHash SHA-256 of the code.
     * @param string $clientInternalId Client::$id.
     * @param string $subject Owner subject.
     * @param string $redirectUri The redirect URI the code was sent to.
     * @param string $resource Canonical resource identifier.
     * @param list<string> $scopes Granted scopes; contains `offline_access` when the client asked for it.
     * @param string $codeChallenge PKCE S256 challenge.
     * @param \DateTimeImmutable $expiresAt Expiry.
     * @param \DateTimeImmutable $createdAt Creation.
     * @param \DateTimeImmutable|null $usedAt When it was exchanged.
     * @param string|null $familyId Token family issued from it.
     */
    public function __construct(
        public readonly string $id,
        public readonly string $codeHash,
        public readonly string $clientInternalId,
        public readonly string $subject,
        public readonly string $redirectUri,
        public readonly string $resource,
        public readonly array $scopes,
        public readonly string $codeChallenge,
        public readonly DateTimeImmutable $expiresAt,
        public readonly DateTimeImmutable $createdAt,
        public readonly ?DateTimeImmutable $usedAt = null,
        public readonly ?string $familyId = null,
    ) {
    }

    /**
     * Whether the code expired at $now.
     */
    public function isExpired(DateTimeImmutable $now): bool
    {
        return $this->expiresAt <= $now;
    }
}
