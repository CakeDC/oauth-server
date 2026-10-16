<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Support;

/**
 * Strict host validation: an IP literal or a plain DNS host name, nothing a URL parser or HTTP client could
 * normalize into a different host (percent-encoding, decimal or hex IPv4 forms, trailing dots).
 *
 * @internal Not part of the public API: it may change in any 1.x release.
 */
final class HostName
{
    /**
     * Whether $host (as parse_url returns it, IPv6 in brackets) is an IP literal or a strict host name.
     */
    public static function isValid(string $host): bool
    {
        if ($host === '' || strlen($host) > 253) {
            return false;
        }
        if (str_starts_with($host, '[')) {
            return str_ends_with($host, ']')
                && filter_var(substr($host, 1, -1), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
        }
        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            return true;
        }
        $labels = explode('.', strtolower($host));
        if (count($labels) < 2) {
            return false;
        }
        foreach ($labels as $label) {
            if (preg_match('/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\z/', $label) !== 1) {
                return false;
            }
        }

        return preg_match('/^[a-z]/', end($labels)) === 1;
    }
}
