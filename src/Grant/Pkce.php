<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Grant;

use CakeDC\OAuth\Server\Support\Base64Url;

/**
 * Proof Key for Code Exchange with the S256 method only (RFC 7636).
 */
final class Pkce
{
    /**
     * Whether $challenge looks like an S256 challenge: base64url of 32 bytes.
     */
    public static function isValidChallenge(string $challenge): bool
    {
        return preg_match('/^[A-Za-z0-9_-]{43}\z/', $challenge) === 1;
    }

    /**
     * Whether $verifier has the RFC 7636 alphabet and length (43 to 128).
     */
    public static function isValidVerifier(string $verifier): bool
    {
        return preg_match('/^[A-Za-z0-9\-._~]{43,128}\z/', $verifier) === 1;
    }

    /**
     * The S256 challenge of $verifier.
     */
    public static function challengeFor(string $verifier): string
    {
        return Base64Url::encode(hash('sha256', $verifier, true));
    }

    /**
     * Whether $verifier is valid and matches $challenge.
     */
    public static function verify(string $verifier, string $challenge): bool
    {
        return self::isValidVerifier($verifier) && hash_equals($challenge, self::challengeFor($verifier));
    }
}
