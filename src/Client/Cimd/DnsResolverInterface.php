<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Client\Cimd;

/**
 * Resolves host names.
 */
interface DnsResolverInterface
{
    /**
     * The IPv4 and IPv6 addresses of $host; empty when the name has no address (it does not exist, or has
     * no A or AAAA record).
     *
     * A lookup that gets no answer (a timeout, a server failure) is not "no address": throw a
     * RuntimeException then. The server treats it as a temporary failure, like a network error, and does
     * not remember it as a rejection of the client.
     *
     * @return list<string>
     * @throws \RuntimeException When the lookup itself failed.
     */
    public function resolve(string $host): array;
}
