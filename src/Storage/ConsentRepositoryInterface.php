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
     * Inserts the consent, or replaces the scopes and modification time of the stored one for the same
     * subject, client and resource (keeping its id and creation time). This holds when two first saves race
     * (a double click on "Allow"): the second replaces the scopes of the first, it never fails on the
     * unique key.
     */
    public function saveConsent(Consent $consent): void;

    /**
     * Deletes the consent of a subject for a client on a resource.
     */
    public function deleteConsent(string $subject, string $clientInternalId, string $resource): void;

    /**
     * Every consent of a subject, oldest first. The subject is compared case-sensitively.
     *
     * @return list<\CakeDC\OAuth\Server\Grant\Consent>
     */
    public function findConsentsBySubject(string $subject): array;

    /**
     * Deletes every consent of a subject and returns how many were deleted. Case-sensitive. Tokens are not
     * touched: revoke them with `TokenRevoker::revokeAllForSubject()`.
     */
    public function deleteConsentsBySubject(string $subject): int;
}
