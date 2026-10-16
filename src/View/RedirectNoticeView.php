<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\View;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Support\HostClass;

/**
 * What the page shows when a failed authorization request could go back to its client, but the
 * redirect URI is not trusted enough to send the person there automatically (RFC 9700 section 4.11.2).
 */
final class RedirectNoticeView
{
    /**
     * @internal Build it through the AuthorizationServer; its constructor may change in any 1.x release.
     * @param \CakeDC\OAuth\Server\Exception\OAuthException $error The error.
     * @param \CakeDC\OAuth\Server\Client\Client|null $client The client, when known.
     * @param string $redirectUri The client's validated redirect URI.
     * @param string $continueUrl The redirect URI with the error parameters: the link that continues.
     */
    public function __construct(
        public readonly OAuthException $error,
        public readonly ?Client $client,
        public readonly string $redirectUri,
        public readonly string $continueUrl,
    ) {
    }

    /**
     * The host the person would be sent to; for a private-use scheme, the scheme with its colon
     * (`com.example.app:`), since what follows it is chosen by the app, and so that a scheme such as
     * `claude.ai:` never reads as the host claude.ai.
     */
    public function redirectHost(): string
    {
        return HostClass::redirectTarget($this->redirectUri);
    }
}
