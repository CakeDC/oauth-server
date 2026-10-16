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
}
