<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Owner;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Resource\ProtectedResource;

/**
 * What the application tells the server about its people. Implemented by the application.
 */
interface UserProviderInterface
{
    /**
     * The owner with this subject, looked up on every protected request; null when the person is
     * gone or no longer active, which makes their tokens fail at once.
     */
    public function findBySubject(string $subject): ?ResourceOwner;

    /**
     * Whether $owner may authorize $client to act on $resource.
     */
    public function canAuthorize(ResourceOwner $owner, Client $client, ProtectedResource $resource): bool;

    /**
     * The scopes $owner may hold on $resource; null for all of them. Checked at consent and again on
     * every request, so a role change applies at once.
     *
     * @return list<string>|null
     */
    public function scopesFor(ResourceOwner $owner, ProtectedResource $resource): ?array;

    /**
     * The identity $client acts as with the client credentials grant; null refuses the grant.
     */
    public function forClient(Client $client, ProtectedResource $resource): ?ResourceOwner;
}
