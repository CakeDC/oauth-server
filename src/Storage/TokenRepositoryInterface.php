<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Storage;

use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Token\Token;
use DateTimeImmutable;

/**
 * Stores access, refresh and personal tokens.
 */
interface TokenRepositoryInterface
{
    /**
     * Inserts a token.
     */
    public function saveToken(Token $token): void;

    /**
     * The token with this hash.
     */
    public function findTokenByHash(string $hash): ?Token;

    /**
     * The token with this internal id.
     */
    public function findTokenById(string $id): ?Token;

    /**
     * Marks a refresh token used, atomically: of two concurrent calls only one returns true. A revoked
     * token is never marked (returns false), so a revocation beats a rotation in flight.
     */
    public function markTokenUsed(string $id, DateTimeImmutable $at): bool;

    /**
     * Revokes one token if it is not revoked yet.
     */
    public function revokeToken(string $id, DateTimeImmutable $at): void;

    /**
     * Revokes the tokens of a family that are not revoked yet; returns how many.
     */
    public function revokeTokenFamily(string $familyId, DateTimeImmutable $at): int;

    /**
     * Revokes every token of a subject that is not revoked yet; returns how many.
     */
    public function revokeTokensBySubject(string $subject, SubjectType $type, DateTimeImmutable $at): int;

    /**
     * Revokes every token of a client that is not revoked yet; returns how many.
     */
    public function revokeTokensByClient(string $clientInternalId, DateTimeImmutable $at): int;

    /**
     * The tokens of a family, oldest first.
     *
     * @return list<\CakeDC\OAuth\Server\Token\Token>
     */
    public function findTokensByFamily(string $familyId): array;

    /**
     * The tokens of a subject that are neither revoked nor expired at $now, oldest first.
     *
     * @return list<\CakeDC\OAuth\Server\Token\Token>
     */
    public function findActiveTokensBySubject(string $subject, SubjectType $type, DateTimeImmutable $now): array;

    /**
     * Records the last use of a token.
     */
    public function touchToken(string $id, DateTimeImmutable $at): void;
}
