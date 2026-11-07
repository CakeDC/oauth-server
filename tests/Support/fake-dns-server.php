<?php
declare(strict_types=1);

/**
 * A DNS server for the BoundedDnsResolver tests, on 127.0.0.1 over UDP and TCP (same port). Prints the
 * port, then answers according to the scenario in the first argument, a JSON object keyed by
 * "host type" ("client.example 1"):
 *
 * - answers: list of [owner, type, value] records (default none)
 * - rcode: response code (default 0)
 * - truncated: answer over UDP with the TC bit and no records, and fully over TCP (default false)
 * - silent: never answer (default false)
 * - noise: first send a packet with another id (default false)
 *
 * A question without a scenario gets NXDOMAIN. Runs until killed.
 */

use CakeDC\OAuth\Server\Test\Support\DnsPackets;

require dirname(__DIR__, 2) . '/vendor/autoload.php';

/** @var array<string, array<string, mixed>> $scenario */
$scenario = json_decode($argv[1] ?? '{}', true) ?: [];
// A free UDP port is not always free over TCP: try again with another one (quietly).
set_error_handler(static fn(): bool => true);
$udp = $tcp = false;
for ($attempt = 0; $attempt < 20 && $tcp === false; $attempt++) {
    $udp = stream_socket_server('udp://127.0.0.1:0', $errno, $errstr, STREAM_SERVER_BIND);
    if ($udp === false) {
        continue;
    }
    $port = (int)substr((string)strrchr((string)stream_socket_get_name($udp, false), ':'), 1);
    $tcp = stream_socket_server('tcp://127.0.0.1:' . $port, $errno, $errstr);
    if ($tcp === false) {
        fclose($udp);
    }
}
restore_error_handler();
if ($udp === false || $tcp === false) {
    fwrite(STDERR, 'No port: ' . $errstr);
    exit(1);
}
fwrite(STDOUT, $port . "\n");
fflush(STDOUT);

/**
 * The answer to $query, or null to stay silent.
 *
 * @param array<string, array<string, mixed>> $scenario
 * @return list<string> Packets to send, in order.
 */
function answer(string $query, array $scenario, bool $overTcp): array
{
    $id = unpack('n', $query)[1];
    $offset = 12;
    $labels = [];
    while (($size = ord($query[$offset])) !== 0) {
        $labels[] = substr($query, $offset + 1, $size);
        $offset += 1 + $size;
    }
    $host = implode('.', $labels);
    $type = unpack('n', $query, $offset + 1)[1];
    $case = $scenario[$host . ' ' . $type] ?? ['rcode' => 3];
    if ($case['silent'] ?? false) {
        return [];
    }
    $truncated = ($case['truncated'] ?? false) && !$overTcp;
    $packets = [];
    if ($case['noise'] ?? false) {
        $packets[] = DnsPackets::response($id + 1 & 0xFFFF, $host, $type, [[$host, $type, $type === 1 ? '10.0.0.1' : 'fd00::1']]);
    }
    $packets[] = DnsPackets::response($id, $host, $type, $truncated ? [] : $case['answers'] ?? [], $case['rcode'] ?? 0, $truncated);

    return $packets;
}

$clients = [];
while (true) {
    $read = array_merge([$udp, $tcp], $clients);
    $write = $except = null;
    if (stream_select($read, $write, $except, 5) === false) {
        exit(1);
    }
    foreach ($read as $socket) {
        if ($socket === $udp) {
            $query = stream_socket_recvfrom($udp, 512, 0, $peer);
            foreach (answer((string)$query, $scenario, false) as $packet) {
                stream_socket_sendto($udp, $packet, 0, (string)$peer);
            }
        } elseif ($socket === $tcp) {
            $client = stream_socket_accept($tcp);
            if ($client !== false) {
                $clients[] = $client;
            }
        } else {
            $length = fread($socket, 2);
            if ($length === false || strlen($length) < 2) {
                fclose($socket);
                $clients = array_values(array_filter($clients, fn($c) => $c !== $socket));
                continue;
            }
            $query = (string)fread($socket, unpack('n', $length)[1]);
            foreach (answer($query, $scenario, true) as $packet) {
                fwrite($socket, pack('n', strlen($packet)) . $packet);
            }
        }
    }
}
