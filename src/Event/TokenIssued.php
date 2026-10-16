<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Event;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Token\Token;

/**
 * A token was issued. The token value is never part of an event.
 */
final class TokenIssued
{
    /**
     * @param \CakeDC\OAuth\Server\Token\Token $token The stored token.
     * @param \CakeDC\OAuth\Server\Client\Client|null $client Its client; null for personal tokens.
     */
    public function __construct(
        public readonly Token $token,
        public readonly ?Client $client,
    ) {
    }
}
