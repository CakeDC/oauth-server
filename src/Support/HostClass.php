<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Support;

/**
 * The one place that decides what a host or a redirect URI points at, so the matcher, the consent
 * page and the consent memory cannot disagree.
 *
 * @internal Not part of the public API: it may change in any 1.x release.
 */
final class HostClass
{
    /**
     * Whether $host, as `parse_url()` returns it, is one of the loopback literals of RFC 8252 section 7.3
     * (`localhost`, `127.0.0.1`, `[::1]`). Only these may be registered for plain http and match ignoring
     * the port.
     */
    public static function isLoopbackLiteral(string $host): bool
    {
        return in_array(strtolower($host), ['localhost', '127.0.0.1', '[::1]', '::1'], true);
    }

    /**
     * Whether $host, as `parse_url()` returns it, reaches the person's own computer: `localhost`, a
     * `.localhost` name (RFC 6761), any loopback address (127.0.0.0/8, `::1`) and the unspecified
     * addresses (`0.0.0.0` and the rest of 0.0.0.0/8, `::`), which macOS and Linux connect to the local
     * machine; also the IPv4-mapped form of those.
     */
    public static function isThisComputer(string $host): bool
    {
        $host = rtrim(strtolower($host), '.');
        if ($host === 'localhost' || str_ends_with($host, '.localhost')) {
            return true;
        }
        $ip = trim($host, '[]');
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            return self::isLocalIpv4First(ip2long($ip) >> 24 & 0xFF);
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
            return false;
        }
        $packed = (string)inet_pton($ip);
        if ($packed === str_repeat("\0", 16) || $packed === str_repeat("\0", 15) . "\x01") {
            return true;
        }

        return str_starts_with($packed, str_repeat("\0", 10) . "\xff\xff")
            && self::isLocalIpv4First(ord($packed[12]));
    }

    /**
     * Whether a redirect to $uri stays on the person's computer, where any program can listen: a loopback
     * or unspecified host, or anything that is not https (a private-use scheme is opened by whichever app
     * claims it). A remote https URI only reaches the server that owns its host.
     */
    public static function redirectStaysOnThisComputer(string $uri): bool
    {
        if (strtolower((string)parse_url($uri, PHP_URL_SCHEME)) !== 'https') {
            return true;
        }
        $host = parse_url($uri, PHP_URL_HOST);

        return !is_string($host) || $host === '' || self::isThisComputer($host);
    }

    /**
     * The host of an http(s) URI, lowercase, or null for anything else (a private-use scheme has no host
     * that anyone vouches for: the app that claims the scheme chose it).
     */
    public static function webHost(string $uri): ?string
    {
        $scheme = strtolower((string)parse_url($uri, PHP_URL_SCHEME));
        $host = parse_url($uri, PHP_URL_HOST);

        return ($scheme === 'http' || $scheme === 'https') && is_string($host) && $host !== ''
            ? strtolower($host)
            : null;
    }

    /**
     * What names the destination of a redirect to $uri: the host of an http(s) URI; the scheme of a
     * private-use one followed by its colon (`claude.ai:`), so a scheme that looks like a host never reads as
     * that host (the scheme is chosen by the client, and so is what follows it); the whole string when it
     * has neither.
     */
    public static function redirectTarget(string $uri): string
    {
        $host = self::webHost($uri);
        if ($host !== null) {
            return $host;
        }
        $scheme = strtolower((string)parse_url($uri, PHP_URL_SCHEME));

        return $scheme !== '' && $scheme !== 'http' && $scheme !== 'https' ? $scheme . ':' : $uri;
    }

    /**
     * Whether an IPv4 address that starts with $octet is this machine (0.0.0.0/8 or 127.0.0.0/8).
     */
    private static function isLocalIpv4First(int $octet): bool
    {
        return $octet === 0 || $octet === 127;
    }
}
