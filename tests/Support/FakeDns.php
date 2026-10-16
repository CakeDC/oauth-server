<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Support;

use CakeDC\OAuth\Server\Client\Cimd\DnsResolverInterface;

class FakeDns implements DnsResolverInterface
{
    /**
     * @var array<string, list<string>>
     */
    public array $answers = ['client.example' => ['93.184.216.34'], 'claude.ai' => ['160.79.104.10']];

    public function resolve(string $host): array
    {
        return $this->answers[$host] ?? [];
    }
}
