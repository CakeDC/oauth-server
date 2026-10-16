<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Storage;

use CakeDC\OAuth\Server\Grant\AuthorizationCode;
use DateTimeImmutable;

/**
 * Stores authorization codes.
 */
interface AuthorizationCodeRepositoryInterface
{
    /**
     * Inserts a code.
     *
     * @throws \RuntimeException When a code with this id already exists; the stored row is left unchanged.
     */
    public function saveCode(AuthorizationCode $code): void;

    /**
     * The code with this hash.
     */
    public function findCodeByHash(string $hash): ?AuthorizationCode;

    /**
     * Marks the code used and records the family issued from it, atomically: of two concurrent
     * calls only one returns true.
     */
    public function consumeCode(string $id, DateTimeImmutable $at, string $familyId): bool;

    /**
     * Deletes the codes of a subject that were not used yet, expired or not, and returns how many. With
     * $clientInternalId, only the codes of that client. The subject is compared case-sensitively. Used
     * codes stay, so a replayed code can still revoke the family it issued.
     *
     * One statement (`DELETE ... WHERE subject = ? AND used_at IS NULL`): a code consumed concurrently is
     * either deleted before it is consumed, so `consumeCode()` returns false, or kept as used.
     */
    public function deleteCodesBySubject(string $subject, ?string $clientInternalId = null): int;

    /**
     * Deletes the codes of a client that were not used yet, expired or not, and returns how many. Used
     * codes stay, like in deleteCodesBySubject().
     */
    public function deleteCodesByClient(string $clientInternalId): int;
}
