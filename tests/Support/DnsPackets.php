<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Support;

/**
 * Builds DNS responses (RFC 1035) for the tests of the bounded resolver.
 */
final class DnsPackets
{
    public const A = 1;

    public const CNAME = 5;

    public const AAAA = 28;

    /**
     * A response to the query $id for $host and $type.
     *
     * @param list<array{0: string, 1: int, 2: string}> $answers Owner name, type and value (an address, or the
     *   target of a CNAME).
     * @param int $rcode Response code: 0 no error, 2 server failure, 3 the name does not exist.
     * @param bool $truncated The TC bit.
     */
    public static function response(
        int $id,
        string $host,
        int $type,
        array $answers = [],
        int $rcode = 0,
        bool $truncated = false,
    ): string {
        $flags = 0x8180 | ($truncated ? 0x0200 : 0) | $rcode;
        $packet = pack('nnnnnn', $id, $flags, 1, count($answers), 0, 0);
        $packet .= self::name($host) . pack('nn', $type, 1);
        foreach ($answers as [$owner, $recordType, $value]) {
            $owner = $owner === $host ? "\xC0\x0C" : self::name($owner);
            $data = match ($recordType) {
                self::A, self::AAAA => (string)inet_pton($value),
                default => self::name($value),
            };
            $packet .= $owner . pack('nnNn', $recordType, 1, 300, strlen($data)) . $data;
        }

        return $packet;
    }

    /**
     * $host in the label format of DNS messages, without compression.
     */
    public static function name(string $host): string
    {
        $encoded = '';
        foreach (explode('.', $host) as $label) {
            $encoded .= chr(strlen($label)) . $label;
        }

        return $encoded . "\0";
    }
}
