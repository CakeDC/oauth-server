<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Client\Cimd;

/**
 * Tells globally routable addresses from private, loopback, link-local and reserved ones, so a
 * client_id URL cannot make the server reach into its own network (SSRF).
 */
final class IpGuard
{
    private const DENIED = [
        '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
        '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15',
        '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
        '::/128', '::1/128', '::ffff:0:0/96', '64:ff9b::/96', '64:ff9b:1::/48', '100::/64', '2001::/23',
        '2001:db8::/32', '2002::/16', 'fc00::/7', 'fe80::/10', 'fec0::/10', 'ff00::/8',
    ];

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
        foreach (self::DENIED as $range) {
            [$network, $bits] = explode('/', $range);
            $prefix = inet_pton($network);
            if (
                $prefix !== false
                && strlen($prefix) === strlen($address)
                && self::inRange($address, $prefix, (int)$bits)
            ) {
                return false;
            }
        }

        return true;
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
