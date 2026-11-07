<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Client\Cimd;

use InvalidArgumentException;
use RuntimeException;

/**
 * Resolves A and AAAA records by asking the nameservers directly, within a time limit.
 *
 * The system resolver behind dns_get_record() follows its own timeouts and retries, which a slow
 * authoritative server of a hostile client_id host can stretch to many seconds per lookup. This resolver
 * sends both queries over UDP to one nameserver at a time and gives up when the time limit has passed. A
 * truncated answer is asked again over TCP; packets that do not answer the query (another id or
 * question) are ignored; a server that fails (SERVFAIL, REFUSED, a malformed answer) or stays silent for
 * its share of the time hands over to the next one. A name that does not exist, or has no address, is no
 * address; no answer within the limit is a RuntimeException, a temporary failure.
 *
 * Like dns_get_record() it does not read /etc/hosts and does not apply search domains (client_id hosts
 * are full names).
 */
final class BoundedDnsResolver implements DnsResolverInterface
{
    /**
     * Each nameserver gets at least this share of the time limit, in seconds.
     */
    private const MIN_SHARE = 0.5;

    /**
     * Largest UDP answer read.
     */
    private const UDP_BYTES = 4096;

    /**
     * @param list<string> $nameservers Addresses with port: "192.0.2.53:53", "[2001:db8::53]:53".
     * @param float $timeout Seconds for the whole lookup.
     * @throws \InvalidArgumentException
     */
    public function __construct(
        public readonly array $nameservers,
        private readonly float $timeout,
    ) {
        if ($nameservers === [] || $timeout <= 0) {
            throw new InvalidArgumentException('A bounded resolver needs a nameserver and a positive timeout.');
        }
    }

    /**
     * A resolver for the nameservers of a resolv.conf file, or null when it names none (or does not exist,
     * as on Windows).
     *
     * @param float $timeout Seconds for the whole lookup.
     * @param string $file The resolv.conf file.
     */
    public static function fromResolvConf(float $timeout, string $file = '/etc/resolv.conf'): ?self
    {
        $lines = is_readable($file) ? file($file, FILE_IGNORE_NEW_LINES) : false;
        $nameservers = [];
        foreach ($lines === false ? [] : $lines as $line) {
            if (preg_match('/^\s*nameserver\s+(\S+)/', $line, $match) !== 1) {
                continue;
            }
            $address = $match[1];
            $bare = explode('%', $address, 2)[0];
            if (filter_var($bare, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                $nameservers[] = $address . ':53';
            } elseif (filter_var($bare, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
                $nameservers[] = '[' . $address . ']:53';
            }
        }

        return $nameservers === [] ? null : new self($nameservers, $timeout);
    }

    /**
     * @inheritDoc
     */
    public function resolve(string $host): array
    {
        // Socket warnings (a refused port, an unreachable network) are answers here, not errors.
        set_error_handler(static fn(): bool => true);
        try {
            return $this->lookup($host);
        } finally {
            restore_error_handler();
        }
    }

    /**
     * The addresses of $host, asking one nameserver after another until the time limit.
     *
     * @return list<string>
     * @throws \RuntimeException When no nameserver answered in time.
     */
    private function lookup(string $host): array
    {
        $deadline = microtime(true) + $this->timeout;
        $share = max(self::MIN_SHARE, $this->timeout / count($this->nameservers));
        while (microtime(true) < $deadline) {
            foreach ($this->nameservers as $nameserver) {
                $left = $deadline - microtime(true);
                if ($left <= 0) {
                    break 2;
                }
                $addresses = $this->ask($nameserver, $host, microtime(true) + min($left, $share));
                if ($addresses !== null) {
                    return $addresses;
                }
            }
        }

        throw new RuntimeException('The DNS lookup got no answer in time.');
    }

    /**
     * The addresses of $host according to $nameserver, or null when it did not answer usefully by $until.
     *
     * @return list<string>|null
     */
    private function ask(string $nameserver, string $host, float $until): ?array
    {
        $socket = stream_socket_client('udp://' . $nameserver, $errno, $error, 0);
        if ($socket === false) {
            return null;
        }
        $pending = [];
        foreach ([DnsMessage::A, DnsMessage::AAAA] as $type) {
            $id = random_int(0, 0xFFFF);
            $pending[$type] = $id;
            if (fwrite($socket, DnsMessage::query($id, $host, $type)) === false) {
                fclose($socket);

                return null;
            }
        }
        $addresses = [];
        stream_set_blocking($socket, false);
        while ($pending !== []) {
            $packet = $this->receive($socket, $until);
            if ($packet === null) {
                fclose($socket);

                return null;
            }
            foreach ($pending as $type => $id) {
                $reply = DnsMessage::read($packet, $id, $host, $type);
                if ($reply->status === DnsReply::TRUNCATED) {
                    $reply = $this->askOverTcp($nameserver, $id, $host, $type, $until);
                }
                if ($reply->status === DnsReply::IGNORED) {
                    continue;
                }
                if ($reply->status === DnsReply::FAILED || $reply->status === DnsReply::TRUNCATED) {
                    fclose($socket);

                    return null;
                }
                array_push($addresses, ...$reply->addresses);
                unset($pending[$type]);
                break;
            }
        }
        fclose($socket);

        return array_values(array_unique($addresses));
    }

    /**
     * The next datagram on $socket, or null when none arrived by $until.
     *
     * @param resource $socket
     */
    private function receive($socket, float $until): ?string
    {
        while (true) {
            $left = $until - microtime(true);
            if ($left <= 0) {
                return null;
            }
            $read = [$socket];
            $write = $except = null;
            $ready = stream_select($read, $write, $except, (int)$left, (int)(($left - (int)$left) * 1000000));
            if ($ready === false) {
                return null;
            }
            if ($ready === 0) {
                continue;
            }
            $packet = fread($socket, self::UDP_BYTES);
            if (is_string($packet) && $packet !== '') {
                return $packet;
            }
            if ($packet === false) {
                // An ICMP "port unreachable" on a connected UDP socket: this server is not there.
                return null;
            }
        }
    }

    /**
     * Asks the query again over TCP (RFC 7766), for an answer that did not fit in UDP.
     */
    private function askOverTcp(string $nameserver, int $id, string $host, int $type, float $until): DnsReply
    {
        $left = $until - microtime(true);
        $socket = $left > 0 ? stream_socket_client('tcp://' . $nameserver, $errno, $error, $left) : false;
        if ($socket === false) {
            return new DnsReply(DnsReply::FAILED);
        }
        $query = DnsMessage::query($id, $host, $type);
        stream_set_blocking($socket, false);
        $sent = fwrite($socket, pack('n', strlen($query)) . $query);
        $length = $sent === false ? null : $this->readStream($socket, 2, $until);
        $size = $length === null ? false : unpack('n', $length);
        $packet = is_array($size) && $size[1] > 0 ? $this->readStream($socket, (int)$size[1], $until) : null;
        fclose($socket);

        return $packet === null ? new DnsReply(DnsReply::FAILED) : DnsMessage::read($packet, $id, $host, $type);
    }

    /**
     * Exactly $bytes from a TCP $socket, or null when they did not arrive by $until.
     *
     * @param resource $socket
     */
    private function readStream($socket, int $bytes, float $until): ?string
    {
        $data = '';
        $missing = $bytes;
        while ($missing > 0) {
            $left = $until - microtime(true);
            if ($left <= 0) {
                return null;
            }
            $read = [$socket];
            $write = $except = null;
            $ready = stream_select($read, $write, $except, (int)$left, (int)(($left - (int)$left) * 1000000));
            if ($ready === false) {
                return null;
            }
            if ($ready === 0) {
                continue;
            }
            $chunk = fread($socket, $missing);
            if ($chunk === false || ($chunk === '' && feof($socket))) {
                return null;
            }
            $data .= $chunk;
            $missing -= strlen($chunk);
        }

        return $data;
    }
}
