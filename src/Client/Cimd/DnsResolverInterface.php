<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Client\Cimd;

/**
 * Resolves host names.
 */
interface DnsResolverInterface
{
    /**
     * The IPv4 and IPv6 addresses of $host; empty when it does not resolve.
     *
     * @return list<string>
     */
    public function resolve(string $host): array;
}
