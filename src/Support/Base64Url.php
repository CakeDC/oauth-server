<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Support;

/**
 * Base64url without padding (RFC 4648, section 5).
 *
 * @internal Not part of the public API: it may change in any 1.x release.
 */
final class Base64Url
{
    /**
     * Encodes bytes.
     */
    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
