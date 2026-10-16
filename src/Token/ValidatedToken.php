<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Token;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Resource\ProtectedResource;

/**
 * A token that passed validation, with the owner and scopes it holds right now.
 */
final class ValidatedToken
{
    /**
     * @param \CakeDC\OAuth\Server\Token\Token $token The stored token.
     * @param \CakeDC\OAuth\Server\Owner\ResourceOwner $owner Its owner, freshly loaded.
     * @param \CakeDC\OAuth\Server\Client\Client|null $client Its client; null for personal tokens.
     * @param \CakeDC\OAuth\Server\Resource\ProtectedResource $resource The resource.
     * @param list<string> $scopes Scopes held now, implied ones included.
     */
    public function __construct(
        public readonly Token $token,
        public readonly ResourceOwner $owner,
        public readonly ?Client $client,
        public readonly ProtectedResource $resource,
        public readonly array $scopes,
    ) {
    }

    /**
     * Whether the token holds $scope.
     */
    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }
}
