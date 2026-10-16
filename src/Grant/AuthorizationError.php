<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Grant;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Exception\OAuthException;
use RuntimeException;

/**
 * A failed authorization request: shown to the person when there is no validated redirect URI,
 * otherwise sent back to the client once the person is signed in (directly when the redirect URI is
 * trusted, through a link on the error page when it is not).
 */
final class AuthorizationError extends RuntimeException
{
    /**
     * @param \CakeDC\OAuth\Server\Exception\OAuthException $error The error.
     * @param string|null $redirectUri The validated redirect URI, or null to show the error.
     * @param string|null $state The state to send back.
     * @param \CakeDC\OAuth\Server\Client\Client|null $client The client the redirect URI belongs to; without
     *   it the redirect URI is never trusted.
     */
    public function __construct(
        public readonly OAuthException $error,
        public readonly ?string $redirectUri = null,
        public readonly ?string $state = null,
        public readonly ?Client $client = null,
    ) {
        parent::__construct($error->getMessage(), 0, $error);
    }

    /**
     * Whether the error can go back to the client.
     */
    public function isRedirectable(): bool
    {
        return $this->redirectUri !== null;
    }
}
