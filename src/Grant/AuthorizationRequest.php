<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Grant;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Resource\ProtectedResource;

/**
 * A validated authorization request.
 */
final class AuthorizationRequest
{
    public const PARAMETERS = [
        'response_type', 'client_id', 'redirect_uri', 'scope', 'state', 'code_challenge',
        'code_challenge_method', 'resource',
    ];

    /**
     * @param \CakeDC\OAuth\Server\Client\Client $client The client.
     * @param string $redirectUri Where to send the result.
     * @param string|null $state Opaque value to send back.
     * @param \CakeDC\OAuth\Server\Resource\ProtectedResource $resource The resource.
     * @param list<string> $scopes Requested scopes, without `offline_access`.
     * @param bool $offlineAccess Whether `offline_access` was requested.
     * @param string $codeChallenge PKCE S256 challenge.
     * @param array<string, string> $params The parameters as received.
     */
    public function __construct(
        public readonly Client $client,
        public readonly string $redirectUri,
        public readonly ?string $state,
        public readonly ProtectedResource $resource,
        public readonly array $scopes,
        public readonly bool $offlineAccess,
        public readonly string $codeChallenge,
        public readonly array $params,
    ) {
    }

    /**
     * The authorization parameters to post again with the consent decision.
     *
     * @return array<string, string>
     */
    public function formFields(): array
    {
        return array_intersect_key($this->params, array_flip(self::PARAMETERS));
    }

    /**
     * A digest of what the owner is asked to approve; the consent form token is bound to it.
     */
    public function fingerprint(): string
    {
        return hash('sha256', json_encode([
            $this->client->clientId,
            $this->redirectUri,
            $this->state,
            $this->resource->identifier,
            $this->scopes,
            $this->offlineAccess,
            $this->codeChallenge,
        ], JSON_THROW_ON_ERROR));
    }
}
