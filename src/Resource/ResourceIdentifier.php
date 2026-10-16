<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Resource;

use CakeDC\OAuth\Server\Support\HostClass;
use InvalidArgumentException;

/**
 * Canonical resource and issuer identifiers (RFC 8707, RFC 8414).
 */
final class ResourceIdentifier
{
    /**
     * The canonical form: lowercase scheme and host, no default port, no trailing slash, no fragment.
     * The path and the query are kept as given.
     *
     * @param string $uri The URL, in any spelling.
     * @throws \InvalidArgumentException When $uri is not an absolute http(s) URL without fragment or credentials.
     */
    public static function canonicalize(string $uri): string
    {
        $parts = parse_url($uri);
        if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
            throw new InvalidArgumentException(sprintf('"%s" is not an absolute URL.', $uri));
        }
        if (str_contains($uri, '#')) {
            throw new InvalidArgumentException(sprintf('"%s" must not contain a fragment.', $uri));
        }
        if (isset($parts['user']) || isset($parts['pass'])) {
            throw new InvalidArgumentException(sprintf('"%s" must not contain credentials.', $uri));
        }
        $scheme = strtolower($parts['scheme']);
        if ($scheme !== 'https' && $scheme !== 'http') {
            throw new InvalidArgumentException(sprintf('"%s" must use http or https.', $uri));
        }
        $port = $parts['port'] ?? null;
        if (($scheme === 'https' && $port === 443) || ($scheme === 'http' && $port === 80)) {
            $port = null;
        }
        $path = $parts['path'] ?? '';
        $path = $path === '/' ? '' : rtrim($path, '/');
        $query = isset($parts['query']) && $parts['query'] !== '' ? '?' . $parts['query'] : '';

        return $scheme . '://' . strtolower($parts['host']) . ($port === null ? '' : ':' . $port) . $path . $query;
    }

    /**
     * Whether $host, as `parse_url()` returns it, is a loopback literal of RFC 8252 (see
     * {@see \CakeDC\OAuth\Server\Support\HostClass::isLoopbackLiteral()}).
     */
    public static function isLoopbackHost(string $host): bool
    {
        return HostClass::isLoopbackLiteral($host);
    }

    /**
     * Rejects plain http except on loopback hosts.
     *
     * @param string $uri The URL.
     * @param string $label What the URL is, for the message.
     * @throws \InvalidArgumentException
     */
    public static function assertSecure(string $uri, string $label): void
    {
        $scheme = strtolower((string)parse_url($uri, PHP_URL_SCHEME));
        $host = (string)parse_url($uri, PHP_URL_HOST);
        if ($scheme === 'https' || ($scheme === 'http' && self::isLoopbackHost($host))) {
            return;
        }

        throw new InvalidArgumentException(sprintf('The %s "%s" must use https.', $label, $uri));
    }
}
