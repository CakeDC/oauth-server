<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Event;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Owner\ResourceOwner;

/**
 * An authorization request was refused.
 */
final class AuthorizationDenied
{
    /**
     * @param \CakeDC\OAuth\Server\Client\Client $client The client.
     * @param \CakeDC\OAuth\Server\Owner\ResourceOwner $owner The signed-in owner.
     * @param string $reason `not_allowed` (the application refused) or `user_denied`.
     */
    public function __construct(
        public readonly Client $client,
        public readonly ResourceOwner $owner,
        public readonly string $reason,
    ) {
    }
}
