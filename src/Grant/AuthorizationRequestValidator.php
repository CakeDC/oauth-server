<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Grant;

use CakeDC\OAuth\Server\Client\ClientResolver;
use CakeDC\OAuth\Server\Client\GrantType;
use CakeDC\OAuth\Server\Client\RedirectUriMatcher;
use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Resource\ResourceRegistry;
use CakeDC\OAuth\Server\Scope\Scopes;

/**
 * Validates authorization requests.
 *
 * @internal Used by the authorize endpoint; not part of the public API, it may change in any 1.x
 * release.
 */
final class AuthorizationRequestValidator
{
    /**
     * @internal Build it through the AuthorizationServer; its constructor may change in any 1.x release.
     * @param \CakeDC\OAuth\Server\Client\ClientResolver $clients Client lookup.
     * @param \CakeDC\OAuth\Server\Resource\ResourceRegistry $resources Resources.
     */
    public function __construct(
        private readonly ClientResolver $clients,
        private readonly ResourceRegistry $resources,
    ) {
    }

    /**
     * The validated request.
     *
     * @param array<string, string> $params Query or form parameters.
     * @param list<string> $repeated Parameter names given more than once.
     * @param string|null $requester The client IP, for the metadata document fetch budget.
     * @throws \CakeDC\OAuth\Server\Grant\AuthorizationError
     */
    public function validate(array $params, array $repeated = [], ?string $requester = null): AuthorizationRequest
    {
        foreach (['client_id', 'redirect_uri'] as $name) {
            if (in_array($name, $repeated, true)) {
                throw new AuthorizationError(
                    OAuthException::invalidRequest(sprintf("'%s' was sent more than once.", $name)),
                );
            }
        }
        $clientId = $params['client_id'] ?? '';
        if ($clientId === '') {
            throw new AuthorizationError(OAuthException::invalidRequest("'client_id' is missing."));
        }
        try {
            $client = $this->clients->resolve($clientId, $requester);
        } catch (OAuthException $e) {
            throw new AuthorizationError($e);
        }
        if ($client === null || $client->isRevoked()) {
            throw new AuthorizationError(OAuthException::invalidClient('This client is unknown.'));
        }
        $redirectUri = $params['redirect_uri'] ?? '';
        if ($redirectUri === '') {
            if (count($client->redirectUris) !== 1) {
                throw new AuthorizationError(OAuthException::invalidRequest("'redirect_uri' is required."));
            }
            $redirectUri = $client->redirectUris[0];
        } elseif (!RedirectUriMatcher::matches($redirectUri, $client->redirectUris)) {
            throw new AuthorizationError(
                OAuthException::invalidRequest("'redirect_uri' is not registered for this client."),
            );
        }

        $state = ($params['state'] ?? '') === '' ? null : $params['state'];
        if ($state !== null && preg_match('/\A[\x20-\x7E]+\z/', $state) !== 1) {
            // RFC 6749 appendix A.5: state is %x20-7E. It cannot be echoed safely, so the error omits it.
            throw new AuthorizationError(
                OAuthException::invalidRequest("'state' may only contain printable ASCII characters."),
                $redirectUri,
                null,
                $client,
            );
        }
        $fail = fn(OAuthException $error): AuthorizationError => new AuthorizationError(
            $error,
            $redirectUri,
            $state,
            $client,
        );
        if ($repeated !== []) {
            throw $fail(OAuthException::invalidRequest(
                sprintf("'%s' was sent more than once.", OAuthException::printable($repeated[0])),
            ));
        }
        $responseType = $params['response_type'] ?? '';
        if ($responseType === '') {
            throw $fail(OAuthException::invalidRequest("'response_type' is missing."));
        }
        if ($responseType !== 'code') {
            throw $fail(OAuthException::unsupportedResponseType("Only 'response_type=code' is supported."));
        }
        if (!$client->allowsGrant(GrantType::AUTHORIZATION_CODE)) {
            throw $fail(OAuthException::unauthorizedClient('This client may not use the authorization code flow.'));
        }
        $challenge = $params['code_challenge'] ?? '';
        if ($challenge === '') {
            throw $fail(OAuthException::invalidRequest("'code_challenge' is required (PKCE with S256)."));
        }
        if (($params['code_challenge_method'] ?? '') !== 'S256') {
            throw $fail(OAuthException::invalidRequest("'code_challenge_method' must be 'S256'."));
        }
        if (!Pkce::isValidChallenge($challenge)) {
            throw $fail(OAuthException::invalidRequest("'code_challenge' is malformed."));
        }
        $resourceParam = $params['resource'] ?? '';
        $resource = $resourceParam === '' ? $this->resources->defaultResource() : $this->resources->get($resourceParam);
        if ($resource === null) {
            throw $fail(OAuthException::invalidTarget('The requested resource is unknown.'));
        }
        try {
            $scopes = Scopes::parse($params['scope'] ?? null);
        } catch (OAuthException $e) {
            throw $fail($e);
        }
        $offlineAccess = in_array(Scopes::OFFLINE_ACCESS, $scopes, true);
        $scopes = array_values(array_diff($scopes, [Scopes::OFFLINE_ACCESS]));
        foreach ($scopes as $scope) {
            if (!$resource->hasScope($scope)) {
                throw $fail(OAuthException::invalidScope(sprintf(
                    "The scope '%s' does not exist on %s.",
                    OAuthException::printable($scope),
                    OAuthException::printable($resource->identifier, 2048),
                )));
            }
        }

        return new AuthorizationRequest(
            $client,
            $redirectUri,
            $state,
            $resource,
            $scopes,
            $offlineAccess,
            $challenge,
            $params,
        );
    }
}
