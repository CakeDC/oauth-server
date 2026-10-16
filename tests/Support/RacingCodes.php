<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Support;

use CakeDC\OAuth\Server\Grant\AuthorizationCode;
use CakeDC\OAuth\Server\Storage\AuthorizationCodeRepositoryInterface;
use Closure;
use DateTimeImmutable;

/**
 * Wraps a code repository to run a concurrent request around the winner's consumeCode().
 */
final class RacingCodes implements AuthorizationCodeRepositoryInterface
{
    /**
     * Runs before the real consumeCode() (the racing request wins).
     */
    public ?Closure $beforeConsume = null;

    /**
     * Runs after a successful consumeCode() (the racing request sees a used code).
     */
    public ?Closure $afterConsume = null;

    /**
     * @var list<string>
     */
    public array $families = [];

    public function __construct(private readonly AuthorizationCodeRepositoryInterface $inner)
    {
    }

    /**
     * @inheritDoc
     */
    public function saveCode(AuthorizationCode $code): void
    {
        $this->inner->saveCode($code);
    }

    /**
     * @inheritDoc
     */
    public function findCodeByHash(string $hash): ?AuthorizationCode
    {
        return $this->inner->findCodeByHash($hash);
    }

    /**
     * @inheritDoc
     */
    public function consumeCode(string $id, DateTimeImmutable $at, string $familyId): bool
    {
        $this->families[] = $familyId;
        if ($this->beforeConsume !== null) {
            $callback = $this->beforeConsume;
            $this->beforeConsume = null;
            $callback();
        }
        $consumed = $this->inner->consumeCode($id, $at, $familyId);
        if ($consumed && $this->afterConsume !== null) {
            $callback = $this->afterConsume;
            $this->afterConsume = null;
            $callback();
        }

        return $consumed;
    }

    /**
     * @inheritDoc
     */
    public function deleteCodesBySubject(string $subject, ?string $clientInternalId = null): int
    {
        return $this->inner->deleteCodesBySubject($subject, $clientInternalId);
    }

    /**
     * @inheritDoc
     */
    public function deleteCodesByClient(string $clientInternalId): int
    {
        return $this->inner->deleteCodesByClient($clientInternalId);
    }
}
