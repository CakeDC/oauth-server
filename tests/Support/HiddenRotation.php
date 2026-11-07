<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Support;

use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Storage\TokenRepositoryInterface;
use CakeDC\OAuth\Server\Token\Token;
use DateTimeImmutable;

/**
 * Token storage that hides the tokens a rotation issued until reveal(), as another process sees a rotation
 * whose winner has marked the token used but not stored the new pair yet.
 */
final class HiddenRotation extends PassThroughTokens
{
    private bool $hidden = true;

    /**
     * @param \CakeDC\OAuth\Server\Storage\TokenRepositoryInterface $tokens The real storage.
     * @param string $parentId The refresh token whose rotation is hidden.
     */
    public function __construct(TokenRepositoryInterface $tokens, private readonly string $parentId)
    {
        parent::__construct($tokens);
    }

    /**
     * Makes the rotation visible.
     */
    public function reveal(): void
    {
        $this->hidden = false;
    }

    public function findTokenByHash(string $hash): ?Token
    {
        return $this->visible(parent::findTokenByHash($hash));
    }

    public function findTokenById(string $id): ?Token
    {
        return $this->visible(parent::findTokenById($id));
    }

    public function findTokensByFamily(string $familyId): array
    {
        return array_values(array_filter(parent::findTokensByFamily($familyId), fn(Token $t): bool => $this->visible($t) !== null));
    }

    public function findActiveTokensBySubject(string $subject, SubjectType $type, DateTimeImmutable $now): array
    {
        return array_values(array_filter(
            parent::findActiveTokensBySubject($subject, $type, $now),
            fn(Token $t): bool => $this->visible($t) !== null,
        ));
    }

    private function visible(?Token $token): ?Token
    {
        return $token !== null && $this->hidden && $token->parentId === $this->parentId ? null : $token;
    }
}
