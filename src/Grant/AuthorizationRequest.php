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
        // Length-prefixed raw values: no encoding step that could fail on invalid UTF-8 (a `state` is arbitrary
        // bytes), and no two different requests can produce the same input.
        $frame = static fn(?string $value): string => $value === null ? '-;' : strlen($value) . ':' . $value . ';';
        $data = $frame($this->client->clientId) . $frame($this->redirectUri) . $frame($this->state)
            . $frame($this->resource->identifier) . count($this->scopes) . '#';
        foreach ($this->scopes as $scope) {
            $data .= $frame($scope);
        }

        return hash('sha256', $data . ($this->offlineAccess ? '1' : '0') . $frame($this->codeChallenge));
    }
}
