<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\View;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Client\ClientType;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Resource\ProtectedResource;
use CakeDC\OAuth\Server\Support\HostClass;

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
     * The host that names the client. For a client that registered itself it is the host the answer
     * goes to (empty for a private-use redirect), never a host the client merely listed: both the name and
     * the registered redirect URIs are chosen by the client.
     */
    public function clientHost(): string
    {
        if ($this->client->type === ClientType::Dynamic) {
            return HostClass::webHost($this->redirectUri) ?? '';
        }

        return $this->client->displayHost();
    }

    /**
     * The host the answer is sent to; for a private-use scheme, the scheme, since what follows it is
     * chosen by the app. The same rule as {@see \CakeDC\OAuth\Server\View\RedirectNoticeView::redirectHost()}.
     */
    public function redirectHost(): string
    {
        return HostClass::redirectTarget($this->redirectUri);
    }

    /**
     * What names the client in the title and the heading: its name for a client an administrator
     * registered, otherwise a host the client cannot choose freely: the `client_id` host of a metadata
     * document, the host its answer goes to for a self-registered client. It is an empty string when no
     * host names the client (a self-registered client with a private-use redirect: anyone can pick any
     * scheme, `claude.ai` included); show a fixed text then, such as the `client.local` message. Never use
     * `client->name` or the registered redirect URIs to name a self-registered client.
     */
    public function clientLabel(): string
    {
        return match ($this->client->type) {
            ClientType::MetadataDocument => $this->clientHost() !== '' ? $this->clientHost() : $this->client->name,
            ClientType::Dynamic => $this->clientHost(),
            default => $this->client->name,
        };
    }

    /**
     * The name a self-registered client declared for itself, to show as an unverified secondary line;
     * null for other clients, or when the name only repeats the host label.
     */
    public function declaredName(): ?string
    {
        if (!$this->isUnverified() || $this->client->name === $this->clientLabel()) {
            return null;
        }

        return $this->client->name;
    }

    /**
     * Whether the client's name is self-asserted.
     */
    public function isUnverified(): bool
    {
        return $this->client->type === ClientType::Dynamic;
    }

    /**
     * Whether the answer goes to a program on this computer: a loopback or unspecified address, a
     * `.localhost` name or a private-use scheme, or the client only redirects there. These are the
     * redirects for which a remembered consent is not enough, so the page warns exactly when
     * `ConsentService::identityIsAssured()` is false for a public client.
     */
    public function isLoopbackOnly(): bool
    {
        return HostClass::redirectStaysOnThisComputer($this->redirectUri)
            || $this->client->redirectsOnlyToLoopback();
    }
}
