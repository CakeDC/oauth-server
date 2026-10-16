<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Token;

/**
 * Why a token was refused.
 */
final class ValidationFailure
{
    /**
     * @param string $description For the client developer.
     * @param string $error The RFC 6750 error code.
     */
    public function __construct(
        public readonly string $description,
        public readonly string $error = 'invalid_token',
    ) {
    }
}
