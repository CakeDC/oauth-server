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
     * Whether $name is usable as a display name: not blank, no control characters.
     */
    public static function isUsableName(string $name): bool
    {
        return trim($name) !== '' && preg_match('/[\x00-\x1F\x7F]/', $name) !== 1;
    }

    /**
     * Whether $url is a plain https URL: RFC 3986 characters only, no user information, a strict host.
     */
    public static function isPublicHttpsUrl(string $url): bool
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
