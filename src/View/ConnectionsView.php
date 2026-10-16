<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\View;

use CakeDC\OAuth\Server\Owner\ResourceOwner;
use SensitiveParameter;

/**
 * What the connections page shows.
 */
final class ConnectionsView
{
    /**
     * @internal Build it through the AuthorizationServer; its constructor may change in any 1.x release.
     * @param \CakeDC\OAuth\Server\Owner\ResourceOwner $owner The signed-in owner.
     * @param list<\CakeDC\OAuth\Server\Connections\Connection> $connections Live connections.
     * @param list<\CakeDC\OAuth\Server\Token\Token> $personalTokens Live personal tokens.
     * @param array<string, array{name: string, scopes: array<string, string>}> $creatable Resources and scopes
     *   for a new token.
     * @param array<string, string> $resourceNames Identifier => name.
     * @param string $formAction Path the forms post to.
     * @param string $formToken Signed form token.
     * @param int $maxDays Longest life of a new personal token.
     * @param bool $personalTokensEnabled Whether creating personal tokens is offered; existing ones are listed either way.
     * @param string|null $newToken A token just created; shown once.
     * @param string|null $error A message about the last action.
     */
    public function __construct(
        public readonly ResourceOwner $owner,
        public readonly array $connections,
        public readonly array $personalTokens,
        public readonly array $creatable,
        public readonly array $resourceNames,
        public readonly string $formAction,
        public readonly string $formToken,
        public readonly int $maxDays,
        public readonly bool $personalTokensEnabled,
        #[SensitiveParameter]
        public readonly ?string $newToken = null,
        public readonly ?string $error = null,
    ) {
    }

    /**
     * The display name of a resource.
     */
    public function resourceName(string $identifier): string
    {
        return $this->resourceNames[$identifier] ?? $identifier;
    }
}
