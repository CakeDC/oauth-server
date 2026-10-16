<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Token;

use CakeDC\OAuth\Server\Exception\OAuthException;
use InvalidArgumentException;

/**
 * Why a token was refused.
 */
final class ValidationFailure
{
    /**
     * @param string $description For the client developer; sent as `error_description` in the body and the
     *   `WWW-Authenticate` challenge, so printable ASCII without `"` and `\` (RFC 6750 section 3).
     * @param string $error The RFC 6750 error code.
     * @throws \InvalidArgumentException When $description has a character RFC 6750 does not allow.
     */
    public function __construct(
        public readonly string $description,
        public readonly string $error = 'invalid_token',
    ) {
        if (!OAuthException::isValidDescription($description)) {
            throw new InvalidArgumentException(
                'An error_description may only contain printable ASCII characters other than " and \\.',
            );
        }
    }
}
