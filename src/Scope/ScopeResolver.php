<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Scope;

use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Resource\ProtectedResource;

/**
 * Decides which scopes are granted and which are held.
 *
 * @internal Not part of the public API: it may change in any 1.x release.
 */
final class ScopeResolver
{
    /**
     * The scopes to grant: the requested ones, or the resource's defaults, that the client and the
     * owner may hold.
     *
     * @param \CakeDC\OAuth\Server\Resource\ProtectedResource $resource The resource.
     * @param list<string> $requested Requested scopes, without `offline_access`.
     * @param list<string>|null $clientAllowed The client's scopes; null for any.
     * @param list<string>|null $ownerAllowed The owner's scopes; null for any.
     * @return list<string>
     * @throws \CakeDC\OAuth\Server\Exception\OAuthException invalid_scope for an unknown scope.
     */
    public function resolve(
        ProtectedResource $resource,
        array $requested,
        ?array $clientAllowed,
        ?array $ownerAllowed,
    ): array {
        foreach ($requested as $scope) {
            if (!$resource->hasScope($scope)) {
                throw OAuthException::invalidScope(sprintf(
                    "The scope '%s' does not exist on %s.",
                    OAuthException::printable($scope),
                    OAuthException::printable($resource->identifier, 2048),
                ));
            }
        }
        $wanted = $requested === [] ? $resource->defaultScopes : $requested;

        return $this->limit($resource, $wanted, $clientAllowed, $ownerAllowed);
    }

    /**
     * The scopes a token holds right now: its granted scopes with what they imply, limited to what the
     * client and the owner may hold today and to what the resource still declares.
     *
     * @param \CakeDC\OAuth\Server\Resource\ProtectedResource $resource The resource.
     * @param list<string> $granted The token's scopes.
     * @param list<string>|null $clientAllowed The client's scopes; null for any.
     * @param list<string>|null $ownerAllowed The owner's scopes; null for any.
     * @return list<string>
     */
    public function effective(
        ProtectedResource $resource,
        array $granted,
        ?array $clientAllowed,
        ?array $ownerAllowed,
    ): array {
        return $this->limit($resource, $resource->expand($granted), $clientAllowed, $ownerAllowed);
    }

    /**
     * What remains of $scopes under the owner's current allowance. With no restriction the scopes are
     * returned as given. Otherwise the scopes are expanded, kept when the expanded allowance contains them,
     * and reduced to the minimal set (a scope implied by another kept scope is dropped), so a demotion
     * from `write` to `read` narrows what is issued to `read` instead of refusing it. Nothing is ever added
     * beyond what the grant implied. A refresh applies it to the new access token only; the refresh token
     * keeps the grant.
     *
     * @param \CakeDC\OAuth\Server\Resource\ProtectedResource $resource The resource.
     * @param list<string> $scopes Granted scopes.
     * @param list<string>|null $ownerAllowed The owner's scopes; null for any.
     * @return list<string>
     */
    public function withinOwnerAllowance(ProtectedResource $resource, array $scopes, ?array $ownerAllowed): array
    {
        if ($ownerAllowed === null) {
            return $scopes;
        }
        $allowed = $resource->expand($ownerAllowed);
        $kept = array_values(array_filter(
            $resource->expand($scopes),
            fn(string $scope): bool => in_array($scope, $allowed, true),
        ));

        return array_values(array_filter(
            $kept,
            function (string $scope) use ($resource, $kept): bool {
                foreach ($kept as $other) {
                    if (
                        $other !== $scope
                        && in_array($scope, $resource->expand([$other]), true)
                        && !in_array($other, $resource->expand([$scope]), true)
                    ) {
                        return false;
                    }
                }

                return true;
            },
        ));
    }

    /**
     * The scopes of a refreshed access token: the current ones, or a subset the client asks for. The new
     * refresh token keeps the current ones either way.
     *
     * @param \CakeDC\OAuth\Server\Resource\ProtectedResource $resource The resource.
     * @param list<string> $current Scopes of the refresh token.
     * @param list<string> $requested Requested scopes; empty keeps the current ones.
     * @return list<string>
     * @throws \CakeDC\OAuth\Server\Exception\OAuthException invalid_scope for a scope not held.
     */
    public function narrow(ProtectedResource $resource, array $current, array $requested): array
    {
        if ($requested === []) {
            return $current;
        }
        $held = $resource->expand($current);
        foreach ($requested as $scope) {
            if (!in_array($scope, $held, true)) {
                throw OAuthException::invalidScope(
                    sprintf("The scope '%s' was not granted.", OAuthException::printable($scope)),
                );
            }
        }

        return $requested;
    }

    /**
     * The $scopes that the resource declares and that both allowances (expanded) contain.
     *
     * @param \CakeDC\OAuth\Server\Resource\ProtectedResource $resource The resource.
     * @param list<string> $scopes Candidate scopes.
     * @param list<string>|null $clientAllowed The client's scopes; null for any.
     * @param list<string>|null $ownerAllowed The owner's scopes; null for any.
     * @return list<string>
     */
    private function limit(
        ProtectedResource $resource,
        array $scopes,
        ?array $clientAllowed,
        ?array $ownerAllowed,
    ): array {
        $client = $clientAllowed === null ? null : $resource->expand($clientAllowed);
        $owner = $ownerAllowed === null ? null : $resource->expand($ownerAllowed);

        return array_values(array_filter(
            $scopes,
            fn(string $scope): bool => $resource->hasScope($scope)
                && ($client === null || in_array($scope, $client, true))
                && ($owner === null || in_array($scope, $owner, true)),
        ));
    }
}
