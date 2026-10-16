<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\View;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Client\ClientType;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Resource\ProtectedResource;

/**
 * What the consent page shows and posts back.
 */
final class ConsentView
{
    /**
     * @internal Build it through the AuthorizationServer; its constructor may change in any 1.x release.
     * @param \CakeDC\OAuth\Server\Client\Client $client The client.
     * @param \CakeDC\OAuth\Server\Owner\ResourceOwner $owner The signed-in owner.
     * @param \CakeDC\OAuth\Server\Resource\ProtectedResource $resource The resource.
     * @param array<string, string> $scopes Scopes to grant => description.
     * @param bool $offlineAccess Whether the client asked to stay connected.
     * @param string $redirectUri Where the answer goes.
     * @param string $formAction Path the form posts to.
     * @param array<string, string> $fields Hidden fields to post back.
     * @param bool $approvedBefore A remembered consent covers the request, but the client's identity cannot
     *   be assured (a public loopback or private-scheme redirect), so the person is asked again.
     */
    public function __construct(
        public readonly Client $client,
        public readonly ResourceOwner $owner,
        public readonly ProtectedResource $resource,
        public readonly array $scopes,
        public readonly bool $offlineAccess,
        public readonly string $redirectUri,
        public readonly string $formAction,
        public readonly array $fields,
        public readonly bool $approvedBefore = false,
    ) {
    }

    /**
     * The host that names the client.
     */
    public function clientHost(): string
    {
        return $this->client->displayHost();
    }

    /**
     * The host the answer is sent to.
     */
    public function redirectHost(): string
    {
        $host = parse_url($this->redirectUri, PHP_URL_HOST);

        return is_string($host) ? strtolower($host) : $this->redirectUri;
    }

    /**
     * Whether the client's name is self-asserted.
     */
    public function isUnverified(): bool
    {
        return $this->client->type === ClientType::Dynamic;
    }

    /**
     * Whether the client only redirects to this computer.
     */
    public function isLoopbackOnly(): bool
    {
        return $this->client->redirectsOnlyToLoopback();
    }
}
