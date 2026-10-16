<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Support;

use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Storage\InMemory\InMemoryStorage;
use CakeDC\OAuth\Server\Storage\TokenRepositoryInterface;
use CakeDC\OAuth\Server\Token\Token;
use DateTimeImmutable;
use RuntimeException;

/**
 * A token repository whose touchToken() always fails; everything else is delegated.
 */
class ThrowingTouchTokens implements TokenRepositoryInterface
{
    public function __construct(private readonly InMemoryStorage $inner)
    {
    }

    public function saveToken(Token $token): void
    {
        $this->inner->saveToken($token);
    }

    public function findTokenByHash(string $hash): ?Token
    {
        return $this->inner->findTokenByHash($hash);
    }

    public function findTokenById(string $id): ?Token
    {
        return $this->inner->findTokenById($id);
    }

    public function markTokenUsed(string $id, DateTimeImmutable $at): bool
    {
        return $this->inner->markTokenUsed($id, $at);
    }

    public function revokeToken(string $id, DateTimeImmutable $at): void
    {
        $this->inner->revokeToken($id, $at);
    }

    public function revokeTokenFamily(string $familyId, DateTimeImmutable $at): int
    {
        return $this->inner->revokeTokenFamily($familyId, $at);
    }

    public function revokeTokensBySubject(string $subject, SubjectType $type, DateTimeImmutable $at): int
    {
        return $this->inner->revokeTokensBySubject($subject, $type, $at);
    }

    public function revokeTokensByClient(string $clientInternalId, DateTimeImmutable $at): int
    {
        return $this->inner->revokeTokensByClient($clientInternalId, $at);
    }

    public function findTokensByFamily(string $familyId): array
    {
        return $this->inner->findTokensByFamily($familyId);
    }

    public function findActiveTokensBySubject(string $subject, SubjectType $type, DateTimeImmutable $now): array
    {
        return $this->inner->findActiveTokensBySubject($subject, $type, $now);
    }

    public function touchToken(string $id, DateTimeImmutable $at): void
    {
        throw new RuntimeException('touch exploded');
    }
}
