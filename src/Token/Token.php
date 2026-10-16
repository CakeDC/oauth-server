<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Token;

use CakeDC\OAuth\Server\Owner\SubjectType;
use DateTimeImmutable;

/**
 * A stored access, refresh or personal token. The token itself is never stored, only its hash.
 */
final class Token
{
    /**
     * @param string $id Internal UUID.
     * @param string $tokenHash SHA-256 of the token.
     * @param \CakeDC\OAuth\Server\Token\TokenType $type Kind.
     * @param string $familyId Tokens from one authorization share it; revoking a connection revokes it.
     * @param string|null $clientInternalId Client::$id; null for personal tokens.
     * @param string $subject Owner subject; the client_id for client credentials.
     * @param \CakeDC\OAuth\Server\Owner\SubjectType $subjectType User or client.
     * @param string $resource Canonical resource identifier.
     * @param list<string> $scopes Granted scopes.
     * @param \DateTimeImmutable $createdAt Creation.
     * @param \DateTimeImmutable|null $expiresAt Expiry; null never expires.
     * @param string|null $name Personal token name.
     * @param string|null $parentId The refresh token whose rotation issued this one.
     * @param \DateTimeImmutable|null $usedAt When a refresh token was rotated.
     * @param \DateTimeImmutable|null $revokedAt Revocation.
     * @param \DateTimeImmutable|null $lastUsedAt Last use against a resource (updated at most once a minute).
     */
    public function __construct(
        public readonly string $id,
        public readonly string $tokenHash,
        public readonly TokenType $type,
        public readonly string $familyId,
        public readonly ?string $clientInternalId,
        public readonly string $subject,
        public readonly SubjectType $subjectType,
        public readonly string $resource,
        public readonly array $scopes,
        public readonly DateTimeImmutable $createdAt,
        public readonly ?DateTimeImmutable $expiresAt = null,
        public readonly ?string $name = null,
        public readonly ?string $parentId = null,
        public readonly ?DateTimeImmutable $usedAt = null,
        public readonly ?DateTimeImmutable $revokedAt = null,
        public readonly ?DateTimeImmutable $lastUsedAt = null,
    ) {
    }

    /**
     * Whether the token expired at $now.
     */
    public function isExpired(DateTimeImmutable $now): bool
    {
        return $this->expiresAt !== null && $this->expiresAt <= $now;
    }

    /**
     * Whether the token is neither revoked nor expired at $now.
     */
    public function isActive(DateTimeImmutable $now): bool
    {
        return $this->revokedAt === null && !$this->isExpired($now);
    }
}
