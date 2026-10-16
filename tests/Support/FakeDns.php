<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Support;

use CakeDC\OAuth\Server\Client\Cimd\DnsResolverInterface;
use RuntimeException;

class FakeDns implements DnsResolverInterface
{
    /**
     * @var array<string, list<string>>
     */
    public array $answers = ['client.example' => ['93.184.216.34'], 'claude.ai' => ['160.79.104.10']];

    /**
     * Hosts whose lookup fails (a resolver timeout or server failure), not "does not exist".
     *
     * @var list<string>
     */
    public array $failing = [];

    /**
     * @var list<string>
     */
    public array $lookups = [];

    public function resolve(string $host): array
    {
        $this->lookups[] = $host;
        if (in_array($host, $this->failing, true)) {
            throw new RuntimeException('DNS lookup of ' . $host . ' failed: a temporary server error occurred.');
        }

        return $this->answers[$host] ?? [];
    }
}
