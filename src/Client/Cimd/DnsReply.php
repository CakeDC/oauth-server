<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Client\Cimd;

/**
 * What a DNS response says about one query.
 *
 * @internal Used by the BoundedDnsResolver; not part of the public API, it may change in any 1.x release.
 */
final class DnsReply
{
    /**
     * The server answered: $addresses holds the addresses of the name (possibly none).
     */
    public const ANSWER = 'answer';

    /**
     * The name does not exist (NXDOMAIN).
     */
    public const NO_NAME = 'no_name';

    /**
     * The server could not answer (SERVFAIL, REFUSED...) or sent a malformed answer.
     */
    public const FAILED = 'failed';

    /**
     * The answer did not fit in UDP: ask again over TCP.
     */
    public const TRUNCATED = 'truncated';

    /**
     * The packet is not an answer to this query: keep waiting.
     */
    public const IGNORED = 'ignored';

    /**
     * @param string $status One of the constants.
     * @param list<string> $addresses Addresses, for ANSWER.
     */
    public function __construct(
        public readonly string $status,
        public readonly array $addresses = [],
    ) {
    }
}
