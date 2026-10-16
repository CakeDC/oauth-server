<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Maintenance;

/**
 * How many rows a prune deleted.
 */
final class PruneResult
{
    /**
     * @param int $codes Authorization codes.
     * @param int $tokens Tokens.
     * @param int $clients Clients.
     */
    public function __construct(
        public readonly int $codes,
        public readonly int $tokens,
        public readonly int $clients,
    ) {
    }
}
