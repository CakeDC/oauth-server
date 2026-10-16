<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Event;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Token\Token;

/**
 * A rotated refresh token was presented again outside the grace window: probably stolen. Its family
 * has been revoked.
 */
final class RefreshTokenReused
{
    /**
     * @param \CakeDC\OAuth\Server\Token\Token $token The reused refresh token.
     * @param \CakeDC\OAuth\Server\Client\Client $client The client that presented it.
     */
    public function __construct(
        public readonly Token $token,
        public readonly Client $client,
    ) {
    }
}
