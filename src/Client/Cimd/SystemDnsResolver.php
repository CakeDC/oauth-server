<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Client\Cimd;

use RuntimeException;

/**
 * Resolves with the system resolver (A and AAAA records). The lookup uses the resolver's own timeouts and
 * retries (resolv.conf), not `cimd.timeout`.
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
        if ($records === false) {
            // dns_get_record() answers [] for a name without records and false when the query failed
            // (a timeout, SERVFAIL): no answer is not a "does not exist".
            throw new RuntimeException('The DNS lookup failed.');
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
