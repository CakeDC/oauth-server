<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Client\Cimd;

use CakeDC\OAuth\Server\Client\Cimd\BoundedDnsResolver;
use CakeDC\OAuth\Server\Test\Support\DnsPackets;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * Runs the resolver against fake DNS servers in processes of their own (tests/Support/fake-dns-server.php).
 * Needs proc_open().
 */
class BoundedDnsResolverTest extends TestCase
{
    /**
     * @var list<array{process: resource, pipes: array<int, resource>}>
     */
    private array $servers = [];

    protected function setUp(): void
    {
        if (!function_exists('proc_open')) {
            $this->markTestSkipped('proc_open() is disabled.');
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->servers as $server) {
            proc_terminate($server['process']);
            foreach ($server['pipes'] as $pipe) {
                fclose($pipe);
            }
            proc_close($server['process']);
        }
    }

    /**
     * Starts a fake server and returns its address.
     *
     * @param array<string, array<string, mixed>> $scenario See fake-dns-server.php.
     */
    private function server(array $scenario): string
    {
        $process = proc_open(
            [PHP_BINARY, dirname(__DIR__, 3) . '/Support/fake-dns-server.php', (string)json_encode($scenario)],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
        );
        $this->assertIsResource($process);
        $this->servers[] = ['process' => $process, 'pipes' => $pipes];
        $port = trim((string)fgets($pipes[1]));
        if (preg_match('/^\d+$/', $port) !== 1) {
            $this->fail('The fake DNS server did not start: ' . stream_get_contents($pipes[2]));
        }

        return '127.0.0.1:' . $port;
    }

    /**
     * @return array<string, array<string, mixed>>
     */
    private static function client(array $a = ['93.184.216.34'], array $aaaa = ['2606:2800:220:1::1']): array
    {
        return [
            'client.example 1' => ['answers' => array_map(fn($ip) => ['client.example', DnsPackets::A, $ip], $a)],
            'client.example 28' => ['answers' => array_map(fn($ip) => ['client.example', DnsPackets::AAAA, $ip], $aaaa)],
        ];
    }

    public function testResolvesBothFamilies(): void
    {
        $resolver = new BoundedDnsResolver([$this->server(self::client())], 2);

        $this->assertSame(['93.184.216.34', '2606:2800:220:1::1'], $resolver->resolve('client.example'));
    }

    public function testANameThatDoesNotExistHasNoAddress(): void
    {
        $resolver = new BoundedDnsResolver([$this->server([])], 2);

        $this->assertSame([], $resolver->resolve('missing.example'));
    }

    public function testASilentServerFailsWithinTheTimeout(): void
    {
        $resolver = new BoundedDnsResolver([$this->server([
            'client.example 1' => ['silent' => true],
            'client.example 28' => ['silent' => true],
        ])], 1);
        $start = microtime(true);

        try {
            $resolver->resolve('client.example');
            $this->fail('Resolved');
        } catch (RuntimeException) {
        }

        $elapsed = microtime(true) - $start;
        $this->assertGreaterThan(0.9, $elapsed);
        $this->assertLessThan(1.5, $elapsed);
    }

    public function testAServerFailureIsNotNoAddress(): void
    {
        $resolver = new BoundedDnsResolver([$this->server([
            'client.example 1' => ['rcode' => 2],
            'client.example 28' => ['rcode' => 2],
        ])], 2);

        $this->expectException(RuntimeException::class);
        $resolver->resolve('client.example');
    }

    public function testTheNextServerAnswersWhenTheFirstIsSilent(): void
    {
        $silent = $this->server([
            'client.example 1' => ['silent' => true],
            'client.example 28' => ['silent' => true],
        ]);
        $resolver = new BoundedDnsResolver([$silent, $this->server(self::client())], 2);

        $this->assertSame(['93.184.216.34', '2606:2800:220:1::1'], $resolver->resolve('client.example'));
    }

    public function testTheNextServerAnswersWhenTheFirstFails(): void
    {
        $failing = $this->server(['client.example 1' => ['rcode' => 5], 'client.example 28' => ['rcode' => 5]]);
        $resolver = new BoundedDnsResolver([$failing, $this->server(self::client())], 2);

        $this->assertSame(['93.184.216.34', '2606:2800:220:1::1'], $resolver->resolve('client.example'));
    }

    public function testATruncatedAnswerIsAskedAgainOverTcp(): void
    {
        $scenario = self::client(['93.184.216.34', '93.184.216.35']);
        $scenario['client.example 1']['truncated'] = true;

        $resolver = new BoundedDnsResolver([$this->server($scenario)], 2);

        $this->assertSame(['93.184.216.34', '93.184.216.35', '2606:2800:220:1::1'], $resolver->resolve('client.example'));
    }

    public function testPacketsWithAnotherIdAreIgnored(): void
    {
        $scenario = self::client();
        $scenario['client.example 1']['noise'] = true;
        $scenario['client.example 28']['noise'] = true;

        $resolver = new BoundedDnsResolver([$this->server($scenario)], 2);

        $this->assertSame(['93.184.216.34', '2606:2800:220:1::1'], $resolver->resolve('client.example'));
    }

    public function testFollowsCnames(): void
    {
        $resolver = new BoundedDnsResolver([$this->server([
            'client.example 1' => ['answers' => [
                ['client.example', 5, 'edge.cdn.example'],
                ['edge.cdn.example', DnsPackets::A, '93.184.216.34'],
            ]],
            'client.example 28' => ['answers' => [['client.example', 5, 'edge.cdn.example']]],
        ])], 2);

        $this->assertSame(['93.184.216.34'], $resolver->resolve('client.example'));
    }

    public function testReadsTheNameserversOfResolvConf(): void
    {
        $file = (string)tempnam(sys_get_temp_dir(), 'resolv');
        file_put_contents($file, implode("\n", [
            '# generated',
            'search corp.example',
            'nameserver 192.0.2.53',
            '; a comment',
            'nameserver 2001:db8::53',
            'nameserver fe80::1%en0',
            'nameserver not-an-address',
            'options timeout:1',
        ]));

        try {
            $this->assertSame(
                ['192.0.2.53:53', '[2001:db8::53]:53', '[fe80::1%en0]:53'],
                BoundedDnsResolver::fromResolvConf(3, $file)?->nameservers,
            );
        } finally {
            unlink($file);
        }
    }

    public function testWithoutNameserversThereIsNoResolver(): void
    {
        $file = (string)tempnam(sys_get_temp_dir(), 'resolv');
        file_put_contents($file, "search corp.example\n");

        try {
            $this->assertNull(BoundedDnsResolver::fromResolvConf(3, $file));
            $this->assertNull(BoundedDnsResolver::fromResolvConf(3, $file . '-missing'));
        } finally {
            unlink($file);
        }
    }
}
