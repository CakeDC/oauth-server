<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Client\Cimd;

/**
 * Resolves with the system resolver (A and AAAA records).
 */
final class SystemDnsResolver implements DnsResolverInterface
{
    /**
     * @inheritDoc
     */
    public function resolve(string $host): array
    {
        set_error_handler(static fn(): bool => true);
        try {
            $records = dns_get_record($host, DNS_A | DNS_AAAA);
        } finally {
            restore_error_handler();
        }
        if (!is_array($records)) {
            return [];
        }
        $addresses = [];
        foreach ($records as $record) {
            foreach (['ip', 'ipv6'] as $key) {
                if (isset($record[$key]) && is_string($record[$key])) {
                    $addresses[] = $record[$key];
                }
            }
        }

        return array_values(array_unique($addresses));
    }
}
