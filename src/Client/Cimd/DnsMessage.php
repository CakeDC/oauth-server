<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Client\Cimd;

/**
 * Writes A and AAAA queries and reads their responses (RFC 1035, section 4).
 *
 * @internal Used by the BoundedDnsResolver; not part of the public API, it may change in any 1.x release.
 */
final class DnsMessage
{
    public const A = 1;

    public const AAAA = 28;

    private const CNAME = 5;

    private const CLASS_IN = 1;

    private const HEADER_BYTES = 12;

    /**
     * Compression pointers followed while reading one name; more is a loop.
     */
    private const MAX_POINTERS = 32;

    /**
     * A recursive query for the $type records of $host.
     */
    public static function query(int $id, string $host, int $type): string
    {
        return pack('nnnnnn', $id, 0x0100, 1, 0, 0, 0) . self::encodeName($host) . pack('nn', $type, self::CLASS_IN);
    }

    /**
     * What $packet says about the query $id for the $type records of $host.
     */
    public static function read(string $packet, int $id, string $host, int $type): DnsReply
    {
        if (strlen($packet) < self::HEADER_BYTES) {
            return new DnsReply(DnsReply::IGNORED);
        }
        /** @var array{id: int, flags: int, questions: int, answers: int} $header */
        $header = unpack('nid/nflags/nquestions/nanswers', $packet);
        if ($header['id'] !== $id || ($header['flags'] & 0x8000) === 0 || $header['questions'] !== 1) {
            return new DnsReply(DnsReply::IGNORED);
        }
        $offset = self::HEADER_BYTES;
        $question = self::readName($packet, $offset);
        if ($question === null || strlen($packet) < $offset + 4) {
            return new DnsReply(DnsReply::IGNORED);
        }
        /** @var array{type: int, class: int} $asked */
        $asked = unpack('ntype/nclass', $packet, $offset);
        $offset += 4;
        if ($question !== strtolower($host) || $asked['type'] !== $type || $asked['class'] !== self::CLASS_IN) {
            return new DnsReply(DnsReply::IGNORED);
        }
        if (($header['flags'] & 0x0200) !== 0) {
            return new DnsReply(DnsReply::TRUNCATED);
        }
        $rcode = $header['flags'] & 0x000F;
        if ($rcode === 3) {
            return new DnsReply(DnsReply::NO_NAME);
        }
        if ($rcode !== 0) {
            return new DnsReply(DnsReply::FAILED);
        }
        $records = self::readRecords($packet, $offset, $header['answers'], $type);

        return $records === null
            ? new DnsReply(DnsReply::FAILED)
            : new DnsReply(DnsReply::ANSWER, self::addressesOf(strtolower($host), $records));
    }

    /**
     * The address and CNAME records of the answer section.
     *
     * @return list<array{0: string, 1: int, 2: string}>|null Owner, type and value; null when malformed.
     */
    private static function readRecords(string $packet, int $offset, int $count, int $type): ?array
    {
        $records = [];
        for ($i = 0; $i < $count; $i++) {
            $owner = self::readName($packet, $offset);
            if ($owner === null || strlen($packet) < $offset + 10) {
                return null;
            }
            /** @var array{type: int, class: int, length: int} $record */
            $record = unpack('ntype/nclass/Nttl/nlength', $packet, $offset);
            $offset += 10;
            $end = $offset + $record['length'];
            if (strlen($packet) < $end) {
                return null;
            }
            if ($record['class'] === self::CLASS_IN && $record['type'] === $type) {
                $size = $type === self::A ? 4 : 16;
                if ($record['length'] !== $size) {
                    return null;
                }
                $address = inet_ntop(substr($packet, $offset, $size));
                if ($address === false) {
                    return null;
                }
                $records[] = [$owner, $type, $address];
            } elseif ($record['class'] === self::CLASS_IN && $record['type'] === self::CNAME) {
                $targetOffset = $offset;
                $target = self::readName($packet, $targetOffset);
                if ($target === null) {
                    return null;
                }
                $records[] = [$owner, self::CNAME, $target];
            }
            $offset = $end;
        }

        return $records;
    }

    /**
     * The addresses of $host: its own records and those of the names its CNAME chain leads to.
     *
     * @param list<array{0: string, 1: int, 2: string}> $records Records.
     * @return list<string>
     */
    private static function addressesOf(string $host, array $records): array
    {
        $names = [$host => true];
        do {
            $grown = false;
            foreach ($records as [$owner, $recordType, $value]) {
                if ($recordType === self::CNAME && isset($names[$owner]) && !isset($names[$value])) {
                    $names[$value] = true;
                    $grown = true;
                }
            }
        } while ($grown);
        $addresses = [];
        foreach ($records as [$owner, $recordType, $value]) {
            if ($recordType !== self::CNAME && isset($names[$owner])) {
                $addresses[] = $value;
            }
        }

        return array_values(array_unique($addresses));
    }

    /**
     * Reads the (possibly compressed) name at $offset, in lower case, and moves $offset past it.
     *
     * @return string|null Null when malformed.
     */
    private static function readName(string $packet, int &$offset): ?string
    {
        $labels = [];
        $position = $offset;
        $jumped = false;
        $pointers = 0;
        $length = 0;
        while (true) {
            if ($position >= strlen($packet)) {
                return null;
            }
            $size = ord($packet[$position]);
            if ($size === 0) {
                if (!$jumped) {
                    $offset = $position + 1;
                }

                return implode('.', $labels);
            }
            if (($size & 0xC0) === 0xC0) {
                if ($position + 1 >= strlen($packet) || ++$pointers > self::MAX_POINTERS) {
                    return null;
                }
                if (!$jumped) {
                    $offset = $position + 2;
                    $jumped = true;
                }
                $position = (($size & 0x3F) << 8) | ord($packet[$position + 1]);
                continue;
            }
            if (($size & 0xC0) !== 0 || $position + 1 + $size > strlen($packet)) {
                return null;
            }
            $length += $size + 1;
            if ($length > 255) {
                return null;
            }
            $labels[] = strtolower(substr($packet, $position + 1, $size));
            $position += 1 + $size;
        }
    }

    /**
     * $host in the label format of DNS messages.
     */
    private static function encodeName(string $host): string
    {
        $encoded = '';
        foreach (explode('.', $host) as $label) {
            $encoded .= chr(min(255, strlen($label))) . $label;
        }

        return $encoded . "\0";
    }
}
