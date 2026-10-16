<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Client;

use CakeDC\OAuth\Server\Resource\ResourceIdentifier;

/**
 * Redirect URI rules: what may be registered, and how a requested URI matches a registered one.
 */
final class RedirectUriMatcher
{
    private const FORBIDDEN_SCHEMES = ['javascript', 'data', 'file', 'vbscript', 'about', 'blob'];

    /**
     * Why $uri cannot be registered for a client of $type, or null when it can.
     */
    public static function registrationError(string $uri, ApplicationType $type, bool $allowPrivateSchemes): ?string
    {
        if ($uri === '' || strlen($uri) > 2000) {
            return 'must be a URI of at most 2000 characters';
        }
        if (preg_match('/[\x00-\x20\x7F]/', $uri) === 1) {
            return 'must not contain spaces or control characters';
        }
        if (str_contains($uri, '#')) {
            return 'must not contain a fragment';
        }
        $scheme = parse_url($uri, PHP_URL_SCHEME);
        if (!is_string($scheme) || preg_match('/^[a-z][a-z0-9+.-]*\z/i', $scheme) !== 1) {
            return 'must be an absolute URI';
        }
        $scheme = strtolower($scheme);
        if (in_array($scheme, self::FORBIDDEN_SCHEMES, true)) {
            return sprintf('must not use the "%s" scheme', $scheme);
        }
        $host = parse_url($uri, PHP_URL_HOST);
        if ($scheme === 'https') {
            return is_string($host) && $host !== '' ? null : 'must name a host';
        }
        if ($scheme === 'http') {
            return is_string($host) && ResourceIdentifier::isLoopbackHost($host)
                ? null
                : 'http is only allowed for loopback addresses (127.0.0.1, [::1], localhost)';
        }
        if ($type !== ApplicationType::Native) {
            return 'web clients must use https';
        }

        return $allowPrivateSchemes ? null : 'private-use URI schemes are not allowed';
    }

    /**
     * Whether $requested matches a registered URI: exactly, or, for loopback http URIs, ignoring
     * the port (RFC 8252, section 7.3).
     *
     * @param list<string> $registered Registered redirect URIs.
     */
    public static function matches(string $requested, array $registered): bool
    {
        foreach ($registered as $uri) {
            if ($requested === $uri || self::isLoopbackMatch($requested, $uri)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Two loopback http URIs that differ only in the port.
     */
    private static function isLoopbackMatch(string $requested, string $registered): bool
    {
        if (str_contains($requested, '#')) {
            return false;
        }
        $a = parse_url($requested);
        $b = parse_url($registered);
        if (!is_array($a) || !is_array($b) || isset($a['user']) || isset($a['pass'])) {
            return false;
        }
        if (strtolower($a['scheme'] ?? '') !== 'http' || strtolower($b['scheme'] ?? '') !== 'http') {
            return false;
        }
        $host = strtolower($a['host'] ?? '');
        if ($host !== strtolower($b['host'] ?? '') || !ResourceIdentifier::isLoopbackHost($host)) {
            return false;
        }

        return ($a['path'] ?? '') === ($b['path'] ?? '') && ($a['query'] ?? null) === ($b['query'] ?? null);
    }
}
