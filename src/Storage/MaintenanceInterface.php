<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Storage;

use CakeDC\OAuth\Server\Maintenance\PruneResult;
use DateTimeImmutable;

/**
 * Deletes what is no longer needed.
 */
interface MaintenanceInterface
{
    /**
     * Deletes expired codes; tokens revoked or expired more than $retentionSeconds ago; and dynamic or
     * metadata document clients older than $unusedClientSeconds, unused for $retentionSeconds and
     * without live tokens, with their codes, tokens and consents.
     */
    public function prune(DateTimeImmutable $now, int $retentionSeconds, int $unusedClientSeconds): PruneResult;
}
