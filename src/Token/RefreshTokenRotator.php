<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Token;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Event\RefreshTokenReused;
use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Owner\UserProviderInterface;
use CakeDC\OAuth\Server\Resource\ProtectedResource;
use CakeDC\OAuth\Server\Resource\ResourceRegistry;
use CakeDC\OAuth\Server\Scope\ScopeResolver;
use CakeDC\OAuth\Server\Storage\TokenRepositoryInterface;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use SensitiveParameter;

/**
 * Exchanges refresh tokens for new pairs, detecting reuse.
 *
 * Replays are judged first: a replay outside the grace window revokes the family whether or not the owner
 * is still active, because a replay is theft evidence either way. Otherwise, a refresh token whose owner
 * no longer exists (a removed person, or a client without an identity) is refused with invalid_grant
 * before it is marked used, and nothing is revoked, so a reactivated person's connection works again
 * without a new consent.
 *
 * @internal Used by the AuthorizationServer's endpoints; not part of the public API, it may change in any
 * 1.x release.
 */
final class RefreshTokenRotator
{
    /**
     * @param \CakeDC\OAuth\Server\Storage\TokenRepositoryInterface $tokens Storage.
     * @param \CakeDC\OAuth\Server\Token\TokenIssuer $issuer Issuer.
     * @param \CakeDC\OAuth\Server\Token\TokenRevoker $revoker Revoker.
     * @param \CakeDC\OAuth\Server\Scope\ScopeResolver $scopes Scopes.
     * @param \CakeDC\OAuth\Server\Resource\ResourceRegistry $resources Resources.
     * @param \Psr\Clock\ClockInterface $clock Clock.
     * @param \Psr\EventDispatcher\EventDispatcherInterface $events Events.
     * @param \CakeDC\OAuth\Server\Owner\UserProviderInterface $users The application's people.
     * @param int $grace Seconds in which a just-rotated token may be presented again; 0 disables.
     */
    public function __construct(
        private readonly TokenRepositoryInterface $tokens,
        private readonly TokenIssuer $issuer,
        private readonly TokenRevoker $revoker,
        private readonly ScopeResolver $scopes,
        private readonly ResourceRegistry $resources,
        private readonly ClockInterface $clock,
        private readonly EventDispatcherInterface $events,
        private readonly UserProviderInterface $users,
        private readonly int $grace = 30,
    ) {
    }

    /**
     * A new access and refresh pair for a refresh token.
     *
     * @param \CakeDC\OAuth\Server\Client\Client $client The authenticated client.
     * @param string $refreshToken The presented refresh token.
     * @param string|null $resource The `resource` parameter, if sent.
     * @param list<string> $requestedScopes Requested scopes; empty keeps the current ones.
     * @throws \CakeDC\OAuth\Server\Exception\OAuthException
     */
    public function rotate(
        Client $client,
        #[SensitiveParameter]
        string $refreshToken,
        ?string $resource,
        array $requestedScopes,
    ): IssuedTokens {
        if ($client->isRevoked()) {
            throw OAuthException::invalidClient('The client was revoked.');
        }
        $now = $this->clock->now();
        $token = $this->tokens->findTokenByHash(TokenGenerator::hash($refreshToken));
        if ($token === null || $token->type !== TokenType::Refresh || $token->clientInternalId !== $client->id) {
            throw OAuthException::invalidGrant('The refresh token is invalid.');
        }
        if ($token->revokedAt !== null) {
            $this->revokedPresented($client, $token, $now);
        }
        // Replays are judged before anything else, so a bad scope or resource cannot dodge detection.
        if ($token->usedAt !== null) {
            return $this->reused($client, $token, $resource, $requestedScopes, $now);
        }
        if ($token->isExpired($now)) {
            throw OAuthException::invalidGrant('The refresh token is no longer valid.');
        }
        [$target, $scopes, $refreshScopes] = $this->prepare($client, $token, $resource, $requestedScopes);
        if ($this->tokens->markTokenUsed($token->id, $now)) {
            return $this->pair($client, $token, $target, $scopes, $refreshScopes);
        }
        $current = $this->tokens->findTokenById($token->id) ?? $token;
        if ($current->revokedAt !== null) {
            $this->revokedPresented($client, $current, $now);
        }

        return $this->reused($client, $current, $resource, $requestedScopes, $now);
    }

    /**
     * Handles a revoked refresh token. When its family still has a live token somebody else holds a
     * newer pair, which is treated as reuse (a takeover); otherwise the token is simply dead.
     *
     * @throws \CakeDC\OAuth\Server\Exception\OAuthException
     */
    private function revokedPresented(Client $client, Token $token, DateTimeImmutable $now): never
    {
        foreach ($this->tokens->findTokensByFamily($token->familyId) as $member) {
            if ($member->isActive($now)) {
                $this->detectedReuse($client, $token);
            }
        }

        throw OAuthException::invalidGrant('The refresh token is no longer valid.');
    }

    /**
     * Revokes the family of a replayed token and answers invalid_grant.
     *
     * @throws \CakeDC\OAuth\Server\Exception\OAuthException
     */
    private function detectedReuse(Client $client, Token $token): never
    {
        $revoked = $this->revoker->revokeFamily($token->familyId, 'refresh_reuse', $token);
        if ($revoked > 0) {
            $this->events->dispatch(new RefreshTokenReused($token, $client));
        }

        throw OAuthException::invalidGrant('The refresh token was already used.');
    }

    /**
     * Checks resource and scopes and works out the scopes of the new pair.
     *
     * The new refresh token keeps the scopes of the presented one, minus those the resource no longer
     * declares (RFC 6749 section 6, OAuth 2.1 section 4.3.3: its scope "MUST be identical"). Only the access
     * token is narrowed: by a requested `scope`, by the client's allowance and by the owner's allowance of
     * today. So a down-scoped refresh, a demotion or a narrowed client loses nothing for good, and the
     * validator still recomputes the scopes on every use.
     *
     * @param list<string> $requestedScopes Requested scopes.
     * @return array{0: \CakeDC\OAuth\Server\Resource\ProtectedResource, 1: list<string>, 2: list<string>} The
     *   resource, the access token's scopes and the refresh token's scopes.
     * @throws \CakeDC\OAuth\Server\Exception\OAuthException
     */
    private function prepare(Client $client, Token $token, ?string $resource, array $requestedScopes): array
    {
        $target = $this->resources->get($token->resource);
        if ($target === null) {
            throw OAuthException::invalidGrant('The resource of this token no longer exists.');
        }
        if ($resource !== null && $resource !== '') {
            $asked = $this->resources->get($resource);
            if ($asked?->identifier !== $target->identifier) {
                throw OAuthException::invalidTarget('The refresh token was issued for another resource.');
            }
        }
        $owner = $token->subjectType === SubjectType::Client
            ? $this->users->forClient($client, $target)
            : $this->users->findBySubject($token->subject);
        if ($owner === null) {
            throw OAuthException::invalidGrant('The owner of this refresh token no longer has access.');
        }
        $scopes = $this->grantable(
            $client,
            $target,
            $this->scopes->narrow($target, $token->scopes, $requestedScopes),
        );
        if ($scopes === []) {
            throw OAuthException::invalidScope('None of the scopes of this token can be granted any more.');
        }
        // The owner's allowance of today, for people and client identities alike (null: unrestricted). A
        // demotion narrows the grant; only when nothing is left is it refused.
        $scopes = $this->scopes->withinOwnerAllowance($target, $scopes, $this->users->scopesFor($owner, $target));
        if ($scopes === []) {
            throw OAuthException::invalidGrant('The grant no longer allows any scope.');
        }
        $grant = array_values(array_unique(array_filter(
            $token->scopes,
            fn(string $scope): bool => $target->hasScope($scope),
        )));

        return [$target, $scopes, $grant];
    }

    /**
     * Drops the scopes the resource no longer declares or the client may no longer hold, and duplicates.
     *
     * @param list<string> $scopes Scopes after narrowing.
     * @return list<string>
     */
    private function grantable(Client $client, ProtectedResource $target, array $scopes): array
    {
        $allowed = $client->scopes === null ? null : $target->expand($client->scopes);

        return array_values(array_unique(array_filter(
            $scopes,
            fn(string $scope): bool => $target->hasScope($scope)
                && ($allowed === null || in_array($scope, $allowed, true)),
        )));
    }

    /**
     * Handles a refresh token presented after it was rotated.
     *
     * Inside the grace window the rotation counts as complete only once a refresh token issued by it
     * exists; until then (a rotation in flight, or an exhausted family) the answer is invalid_grant and
     * nothing is revoked. The one caller that atomically marks that refresh child used revokes the
     * rotation's children and issues the fresh pair. A caller that loses the mark finds the child used
     * (rotated by the client, or taken by another retry) and is treated as reuse: the two cases cannot
     * be told apart from storage, and failing closed costs one re-authorization.
     *
     * @param list<string> $requestedScopes Requested scopes.
     * @throws \CakeDC\OAuth\Server\Exception\OAuthException
     */
    private function reused(
        Client $client,
        Token $token,
        ?string $resource,
        array $requestedScopes,
        DateTimeImmutable $now,
    ): IssuedTokens {
        $usedAt = $token->usedAt ?? $now;
        if ($this->grace > 0 && $now->getTimestamp() - $usedAt->getTimestamp() <= $this->grace) {
            $children = array_values(array_filter(
                $this->tokens->findTokensByFamily($token->familyId),
                fn(Token $child): bool => $child->parentId === $token->id,
            ));
            $refreshChildren = array_values(array_filter(
                $children,
                fn(Token $child): bool => $child->type === TokenType::Refresh && $child->revokedAt === null,
            ));
            $hasRefreshChild = array_filter($children, fn(Token $child): bool => $child->type === TokenType::Refresh);
            if ($hasRefreshChild === []) {
                throw OAuthException::invalidGrant('The refresh token is being rotated; try again.');
            }
            if ($refreshChildren !== [] && !$this->anyUsed($children)) {
                [$target, $scopes, $refreshScopes] = $this->prepare($client, $token, $resource, $requestedScopes);
                $child = $refreshChildren[count($refreshChildren) - 1];
                if ($this->tokens->markTokenUsed($child->id, $now)) {
                    $this->revoker->revokeTokens($children, 'grace', $token);

                    return $this->pair($client, $token, $target, $scopes, $refreshScopes);
                }
            }
        }
        $this->detectedReuse($client, $token);
    }

    /**
     * Whether the tokens of a rotation were put to use. A refresh child that was rotated counts while it
     * is not revoked (a revoked, used one was superseded by an earlier grace re-issue); any child that
     * was presented to a resource counts even if it is revoked.
     *
     * @param list<\CakeDC\OAuth\Server\Token\Token> $children Tokens issued by the rotation.
     */
    private function anyUsed(array $children): bool
    {
        foreach ($children as $child) {
            if ($child->lastUsedAt !== null || ($child->usedAt !== null && $child->revokedAt === null)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Issues the pair that replaces $token, unless $token was revoked meanwhile.
     *
     * @param list<string> $scopes Scopes of the access token.
     * @param list<string> $refreshScopes Scopes of the refresh token.
     * @throws \CakeDC\OAuth\Server\Exception\OAuthException
     */
    private function pair(
        Client $client,
        Token $token,
        ProtectedResource $target,
        array $scopes,
        array $refreshScopes,
    ): IssuedTokens {
        $issued = $this->issuer->issue(
            $client,
            $token->subject,
            $token->subjectType,
            $target,
            $scopes,
            $token->familyId,
            true,
            $token->id,
            $token->familyStartedAt ?? $token->createdAt,
            $refreshScopes,
        );
        if ($this->tokens->findTokenById($token->id)?->revokedAt !== null) {
            $this->revoker->revokeTokens(
                $issued->refresh === null ? [$issued->access] : [$issued->access, $issued->refresh],
                'rotation_revoked',
                $token,
            );

            throw OAuthException::invalidGrant('The refresh token was revoked.');
        }

        return $issued;
    }
}
