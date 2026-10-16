<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Client\Cimd;

/**
 * Tells globally routable addresses from private, loopback, link-local and reserved ones, so a
 * client_id URL cannot make the server reach into its own network (SSRF).
 */
final class IpGuard
{
    private const DENIED_V4 = [
        '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
        '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15',
        '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4', '255.255.255.255/32',
    ];

    /**
     * IPv6 is an allowlist: only global unicast 2000::/3 minus these special ranges.
     */
    private const DENIED_V6 = ['2001::/23', '2001:db8::/32', '2002::/16', '3fff::/20'];

    /**
     * Whether $ip is a valid, globally routable address.
     */
    public static function isPublic(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }
        $address = inet_pton($ip);
        if ($address === false) {
            return false;
        }
        if (strlen($address) === 16) {
            if (!self::inRange($address, (string)inet_pton('2000::'), 3)) {
                return false;
            }

            return !self::inAny($address, self::DENIED_V6);
        }

        return !self::inAny($address, self::DENIED_V4);
    }

    /**
     * Whether the packed $address is inside any of the CIDR $ranges.
     *
     * @param list<string> $ranges CIDR ranges of the same family as $address.
     */
    private static function inAny(string $address, array $ranges): bool
    {
        foreach ($ranges as $range) {
            [$network, $bits] = explode('/', $range);
            $prefix = inet_pton($network);
            if ($prefix !== false && self::inRange($address, $prefix, (int)$bits)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the first $bits bits of two packed addresses are equal.
     */
    private static function inRange(string $address, string $prefix, int $bits): bool
    {
        $bytes = intdiv($bits, 8);
        if (substr($address, 0, $bytes) !== substr($prefix, 0, $bytes)) {
            return false;
        }
        $rest = $bits % 8;
        if ($rest === 0) {
            return true;
        }
        $mask = (0xFF << 8 - $rest) & 0xFF;

        return (ord($address[$bytes]) & $mask) === (ord($prefix[$bytes]) & $mask);
    }
}
