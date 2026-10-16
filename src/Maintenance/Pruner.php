<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Maintenance;

use CakeDC\OAuth\Server\Storage\MaintenanceInterface;
use Psr\Clock\ClockInterface;

/**
 * Deletes expired codes, old dead tokens and abandoned clients. Run it from cron.
 */
final class Pruner
{
    /**
     * @param \CakeDC\OAuth\Server\Storage\MaintenanceInterface $storage Storage.
     * @param \Psr\Clock\ClockInterface $clock Clock.
     * @param int $retentionDays Days revoked and expired tokens are kept.
     * @param int $unusedClientSeconds Age after which a dynamic client without tokens is deleted.
     */
    public function __construct(
        private readonly MaintenanceInterface $storage,
        private readonly ClockInterface $clock,
        private readonly int $retentionDays = 7,
        private readonly int $unusedClientSeconds = 86400,
    ) {
    }

    /**
     * Deletes what is no longer needed.
     */
    public function prune(): PruneResult
    {
        return $this->storage->prune($this->clock->now(), $this->retentionDays * 86400, $this->unusedClientSeconds);
    }
}
