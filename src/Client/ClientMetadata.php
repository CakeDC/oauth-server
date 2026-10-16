<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Client;

use CakeDC\OAuth\Server\Support\HostName;

/**
 * Checks of the display fields of client metadata (names and URLs), shared by every way a client is created.
 */
final class ClientMetadata
{
    /**
     * Whether $name is usable as a display name: valid UTF-8, no control or format characters (`\p{Cc}`
     * and `\p{Cf}`: newlines, bidirectional overrides, zero-width characters), and at least one visible
     * character (not only spaces or characters that draw nothing).
     */
    public static function isUsableName(string $name): bool
    {
        return preg_match('/[\p{Cc}\p{Cf}]/u', $name) === 0
            && preg_match('/[^\p{Z}\p{C}\x{115F}\x{1160}\x{2800}\x{3164}\x{FFA0}]/u', $name) === 1;
    }

    /**
     * The length of $name in characters, not bytes; a string that is not valid UTF-8 is infinitely long.
     */
    public static function characterLength(string $name): int
    {
        $length = preg_match_all('/./su', $name);

        return $length === false ? PHP_INT_MAX : $length;
    }

    /**
     * Whether $url is a plain https URL: RFC 3986 characters only, no user information, a strict host name or
     * IP literal. This is a syntax check for display: the server never fetches these URLs, and renderers
     * must still escape them.
     */
    public static function isDisplayableHttpsUrl(string $url): bool
    {
        if (strlen($url) > 2000 || preg_match(RedirectUriMatcher::URI_CHARACTERS, $url) !== 1) {
            return false;
        }
        $parts = parse_url($url);
        if (!is_array($parts) || isset($parts['user']) || isset($parts['pass'])) {
            return false;
        }
        $host = $parts['host'] ?? '';

        return strtolower($parts['scheme'] ?? '') === 'https' && HostName::isValid($host);
    }
}
