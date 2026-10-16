<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Grant;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Event\ConsentGranted;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Resource\ProtectedResource;
use CakeDC\OAuth\Server\Storage\ConsentRepositoryInterface;
use CakeDC\OAuth\Server\Support\HostClass;
use CakeDC\OAuth\Server\Support\Uuid;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Remembers what owners accepted, so they are asked only once per client, resource and scope when the
 * client's identity is assured.
 */
final class ConsentService
{
    /**
     * @internal Build it through the AuthorizationServer; its constructor may change in any 1.x release.
     * @param \CakeDC\OAuth\Server\Storage\ConsentRepositoryInterface $consents Storage.
     * @param \Psr\Clock\ClockInterface $clock Clock.
     * @param \Psr\EventDispatcher\EventDispatcherInterface $events Events.
     */
    public function __construct(
        private readonly ConsentRepositoryInterface $consents,
        private readonly ClockInterface $clock,
        private readonly EventDispatcherInterface $events,
    ) {
    }

    /**
     * Whether $owner already accepted every scope in $scopes for $client on $resource.
     *
     * @param list<string> $scopes Scopes.
     */
    public function isGranted(ResourceOwner $owner, Client $client, ProtectedResource $resource, array $scopes): bool
    {
        $consent = $this->consents->findConsent($owner->subject, $client->id, $resource->identifier);

        return $consent !== null && $consent->covers($scopes);
    }

    /**
     * Whether $owner accepted $client before, for any resource.
     */
    public function hasConsented(ResourceOwner $owner, Client $client): bool
    {
        foreach ($this->consents->findConsentsBySubject($owner->subject) as $consent) {
            if ($consent->clientInternalId === $client->id) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether a remembered consent may answer for $client without showing the page (RFC 8252 section
     * 8.6): a confidential client proves who it is with its secret when it redeems the code, and an https
     * redirect URI that is not on this computer only reaches the server that owns the host. A loopback or
     * private-scheme redirect URI can be served by any program on the person's computer, which then
     * chooses the PKCE challenge too, so the person is asked every time.
     */
    public function identityIsAssured(Client $client, string $redirectUri): bool
    {
        return !$client->isPublic() || !HostClass::redirectStaysOnThisComputer($redirectUri);
    }

    /**
     * Records an approval, adding $scopes to the ones accepted before.
     *
     * @param list<string> $scopes Scopes.
     */
    public function grant(ResourceOwner $owner, Client $client, ProtectedResource $resource, array $scopes): Consent
    {
        $existing = $this->consents->findConsent($owner->subject, $client->id, $resource->identifier);
        $now = $this->clock->now();
        $consent = new Consent(
            $existing->id ?? Uuid::v4(),
            $owner->subject,
            $client->id,
            $resource->identifier,
            array_values(array_unique([...($existing->scopes ?? []), ...$scopes])),
            $existing->createdAt ?? $now,
            $now,
        );
        $this->consents->saveConsent($consent);
        $this->events->dispatch(new ConsentGranted($consent, $owner, $client));

        return $consent;
    }

    /**
     * Forgets an approval, so the owner is asked again.
     */
    public function forget(string $subject, string $clientInternalId, string $resource): void
    {
        $this->consents->deleteConsent($subject, $clientInternalId, $resource);
    }
}
