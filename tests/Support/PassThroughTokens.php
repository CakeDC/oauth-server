<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Support;

use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Storage\TokenRepositoryInterface;
use CakeDC\OAuth\Server\Token\Token;
use DateTimeImmutable;

/**
 * Token storage that passes every call through, for tests that change one answer.
 */
class PassThroughTokens implements TokenRepositoryInterface
{
    public function __construct(private readonly TokenRepositoryInterface $tokens)
    {
    }

    public function saveToken(Token $token): void
    {
        $this->tokens->saveToken($token);
    }

    public function findTokenByHash(string $hash): ?Token
    {
        return $this->tokens->findTokenByHash($hash);
    }

    public function findTokenById(string $id): ?Token
    {
        return $this->tokens->findTokenById($id);
    }

    public function markTokenUsed(string $id, DateTimeImmutable $at): bool
    {
        return $this->tokens->markTokenUsed($id, $at);
    }

    public function revokeToken(string $id, DateTimeImmutable $at): void
    {
        $this->tokens->revokeToken($id, $at);
    }

    public function revokeTokenFamily(string $familyId, DateTimeImmutable $at): int
    {
        return $this->tokens->revokeTokenFamily($familyId, $at);
    }

    public function revokeTokensBySubject(string $subject, SubjectType $type, DateTimeImmutable $at): int
    {
        return $this->tokens->revokeTokensBySubject($subject, $type, $at);
    }

    public function revokeTokensByClient(string $clientInternalId, DateTimeImmutable $at): int
    {
        return $this->tokens->revokeTokensByClient($clientInternalId, $at);
    }

    public function findTokensByFamily(string $familyId): array
    {
        return $this->tokens->findTokensByFamily($familyId);
    }

    public function findActiveTokensBySubject(string $subject, SubjectType $type, DateTimeImmutable $now): array
    {
        return $this->tokens->findActiveTokensBySubject($subject, $type, $now);
    }

    public function touchToken(string $id, DateTimeImmutable $at): void
    {
        $this->tokens->touchToken($id, $at);
    }
}
