<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Storage;

use CakeDC\OAuth\Server\Grant\Consent;

/**
 * Stores consents, one per subject, client and resource.
 */
interface ConsentRepositoryInterface
{
    /**
     * The consent of a subject for a client on a resource.
     */
    public function findConsent(string $subject, string $clientInternalId, string $resource): ?Consent;

    /**
     * Inserts the consent, or replaces the scopes of the stored one for the same subject, client and
     * resource (keeping its id and creation time).
     */
    public function saveConsent(Consent $consent): void;

    /**
     * Deletes the consent of a subject for a client on a resource.
     */
    public function deleteConsent(string $subject, string $clientInternalId, string $resource): void;
}
