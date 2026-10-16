<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Token;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Event\RefreshTokenReused;
use CakeDC\OAuth\Server\Event\TokenRevoked;
use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Resource\ProtectedResource;
use CakeDC\OAuth\Server\Resource\ResourceRegistry;
use CakeDC\OAuth\Server\Scope\ScopeResolver;
use CakeDC\OAuth\Server\Storage\TokenRepositoryInterface;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Exchanges refresh tokens for new pairs, detecting reuse.
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
        string $refreshToken,
        ?string $resource,
        array $requestedScopes,
    ): IssuedTokens {
        $now = $this->clock->now();
        $token = $this->tokens->findTokenByHash(TokenGenerator::hash($refreshToken));
        if ($token === null || $token->type !== TokenType::Refresh || $token->clientInternalId !== $client->id) {
            throw OAuthException::invalidGrant('The refresh token is invalid.');
        }
        if ($token->revokedAt !== null || $token->isExpired($now)) {
            throw OAuthException::invalidGrant('The refresh token is no longer valid.');
        }
        $target = $this->resources->get($token->resource);
        if ($target === null) {
            throw OAuthException::invalidGrant('The resource of this token no longer exists.');
        }
        $asked = $resource === null || $resource === '' ? null : $this->resources->get($resource);
        if ($resource !== null && $resource !== '' && $asked?->identifier !== $target->identifier) {
            throw OAuthException::invalidTarget('The refresh token was issued for another resource.');
        }
        $scopes = $this->grantable(
            $client,
            $target,
            $this->scopes->narrow($target, $token->scopes, $requestedScopes),
        );
        if ($token->usedAt === null && $this->tokens->markTokenUsed($token->id, $now)) {
            return $this->pair($client, $token, $target, $scopes);
        }

        return $this->reused($client, $this->tokens->findTokenById($token->id) ?? $token, $target, $scopes, $now);
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
     * @param list<string> $scopes Scopes for a new pair.
     * @throws \CakeDC\OAuth\Server\Exception\OAuthException
     */
    private function reused(
        Client $client,
        Token $token,
        ProtectedResource $target,
        array $scopes,
        DateTimeImmutable $now,
    ): IssuedTokens {
        $usedAt = $token->usedAt ?? $now;
        if ($this->grace > 0 && $now->getTimestamp() - $usedAt->getTimestamp() <= $this->grace) {
            $children = array_values(array_filter(
                $this->tokens->findTokensByFamily($token->familyId),
                fn(Token $child): bool => $child->parentId === $token->id && $child->revokedAt === null,
            ));
            if ($children === []) {
                throw OAuthException::invalidGrant('The refresh token is being rotated; try again.');
            }
            $used = array_filter(
                $children,
                fn(Token $child): bool => $child->usedAt !== null || $child->lastUsedAt !== null,
            );
            if ($used === []) {
                foreach ($children as $child) {
                    $this->tokens->revokeToken($child->id, $now);
                }
                $this->events->dispatch(
                    new TokenRevoked('grace', count($children), $token, $token->familyId),
                );

                return $this->pair($client, $token, $target, $scopes);
            }
        }
        $this->revoker->revokeFamily($token->familyId, 'refresh_reuse', $token);
        $this->events->dispatch(new RefreshTokenReused($token, $client));

        throw OAuthException::invalidGrant('The refresh token was already used.');
    }

    /**
     * Issues the pair that replaces $token.
     *
     * @param list<string> $scopes Scopes.
     */
    private function pair(Client $client, Token $token, ProtectedResource $target, array $scopes): IssuedTokens
    {
        $family = $this->tokens->findTokensByFamily($token->familyId);

        return $this->issuer->issue(
            $client,
            $token->subject,
            $token->subjectType,
            $target,
            $scopes,
            $token->familyId,
            true,
            $token->id,
            $family === [] ? $token->createdAt : $family[0]->createdAt,
        );
    }
}
