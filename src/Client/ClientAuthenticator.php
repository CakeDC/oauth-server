<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Client;

use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Http\BasicCredentials;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Authenticates the client of a token, revocation or introspection request with the method it
 * registered.
 *
 * @internal Built through the AuthorizationServer factories, not by you: get it from the server.
 * Its constructor may change in any 1.x release.
 */
final class ClientAuthenticator
{
    private const FAILED = 'Client authentication failed.';

    /**
     * @param \CakeDC\OAuth\Server\Client\ClientResolver $clients Client lookup.
     */
    public function __construct(private readonly ClientResolver $clients)
    {
    }

    /**
     * The authenticated client.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request (for Basic credentials).
     * @param array<string, mixed> $body Form parameters; untrusted, so values may be arrays.
     * @param string|null $requester The client IP, for the metadata document fetch budget.
     * @throws \CakeDC\OAuth\Server\Exception\OAuthException invalid_client or invalid_request.
     */
    public function authenticate(ServerRequestInterface $request, array $body, ?string $requester = null): Client
    {
        $basic = BasicCredentials::fromRequest($request);
        $bodySecret = $body['client_secret'] ?? null;
        if (!is_string($bodySecret) && $bodySecret !== null) {
            throw OAuthException::invalidRequest('client_secret must be a string.');
        }
        if (isset($body['client_id']) && !is_string($body['client_id'])) {
            throw OAuthException::invalidRequest('client_id must be a string.');
        }
        if ($basic !== null && $bodySecret !== null) {
            throw OAuthException::invalidRequest('Use one client authentication method, not two.');
        }
        if ($basic !== null) {
            [$clientId, $secret] = $basic;
            if (isset($body['client_id']) && $body['client_id'] !== $clientId) {
                throw OAuthException::invalidRequest('client_id does not match the credentials.');
            }
            $method = ClientAuthMethod::SecretBasic;
        } else {
            $clientId = $body['client_id'] ?? '';
            if ($clientId === '') {
                throw OAuthException::invalidClient('Client authentication is required.');
            }
            $secret = $bodySecret;
            $method = $secret === null ? ClientAuthMethod::None : ClientAuthMethod::SecretPost;
        }
        $usedBasic = $basic !== null;
        try {
            $client = $this->clients->resolve($clientId, $requester);
        } catch (OAuthException $e) {
            throw $e->error === 'invalid_client' ? OAuthException::invalidClient($e->getMessage(), $usedBasic) : $e;
        }
        if ($client === null || $client->isRevoked() || $client->authMethod !== $method) {
            throw OAuthException::invalidClient(self::FAILED, $usedBasic);
        }
        if ($method !== ClientAuthMethod::None) {
            $given = TokenGenerator::hash((string)$secret);
            if ($client->secretHash === null || !hash_equals($client->secretHash, $given)) {
                throw OAuthException::invalidClient(self::FAILED, $usedBasic);
            }
        }

        return $client;
    }
}
