<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Grant;

use CakeDC\OAuth\Server\Exception\OAuthException;
use RuntimeException;

/**
 * A failed authorization request: shown to the person when the redirect URI cannot be trusted,
 * otherwise sent back to the client.
 */
final class AuthorizationError extends RuntimeException
{
    /**
     * @param \CakeDC\OAuth\Server\Exception\OAuthException $error The error.
     * @param string|null $redirectUri The trusted redirect URI, or null to show the error.
     * @param string|null $state The state to send back.
     */
    public function __construct(
        public readonly OAuthException $error,
        public readonly ?string $redirectUri = null,
        public readonly ?string $state = null,
    ) {
        parent::__construct($error->getMessage(), 0, $error);
    }

    /**
     * Whether the error goes back to the client.
     */
    public function isRedirectable(): bool
    {
        return $this->redirectUri !== null;
    }
}
