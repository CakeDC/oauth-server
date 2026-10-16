<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Token;

use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Owner\UserProviderInterface;
use CakeDC\OAuth\Server\Resource\ResourceRegistry;
use CakeDC\OAuth\Server\Scope\ScopeResolver;
use CakeDC\OAuth\Server\Storage\ClientRepositoryInterface;
use CakeDC\OAuth\Server\Storage\TokenRepositoryInterface;
use InvalidArgumentException;
use Psr\Clock\ClockInterface;
use SensitiveParameter;
use Throwable;

/**
 * Validates access and personal tokens presented to a protected resource.
 */
final class TokenValidator
{
    /**
     * @internal Build it through the AuthorizationServer; its constructor may change in any 1.x release.
     * @param \CakeDC\OAuth\Server\Storage\TokenRepositoryInterface $tokens Token storage.
     * @param \CakeDC\OAuth\Server\Storage\ClientRepositoryInterface $clients Client storage.
     * @param \CakeDC\OAuth\Server\Owner\UserProviderInterface $users The application's people.
     * @param \CakeDC\OAuth\Server\Resource\ResourceRegistry $resources Resources.
     * @param \CakeDC\OAuth\Server\Scope\ScopeResolver $scopes Scopes.
     * @param \Psr\Clock\ClockInterface $clock Clock.
     * @param int $touchInterval Least seconds between two `last_used_at` updates.
     * @param bool $personalTokens Whether personal tokens are accepted; off, they stop working at once.
     */
    public function __construct(
        private readonly TokenRepositoryInterface $tokens,
        private readonly ClientRepositoryInterface $clients,
        private readonly UserProviderInterface $users,
        private readonly ResourceRegistry $resources,
        private readonly ScopeResolver $scopes,
        private readonly ClockInterface $clock,
        private readonly int $touchInterval = 60,
        private readonly bool $personalTokens = true,
    ) {
    }

    /**
     * Checks $token presented to $resource.
     *
     * @param string $token The token value.
     * @param string $resource The resource identifier.
     * @param bool $touch Whether to record the use (`last_used_at`); introspection passes false.
     * @throws \InvalidArgumentException When $resource is not declared (a configuration error).
     */
    public function validate(
        #[SensitiveParameter]
        string $token,
        string $resource,
        bool $touch = true,
    ): ValidatedToken|ValidationFailure {
        $target = $this->resources->get($resource);
        if ($target === null) {
            throw new InvalidArgumentException(sprintf('The resource "%s" is not declared.', $resource));
        }
        $now = $this->clock->now();
        $stored = $this->tokens->findTokenByHash(TokenGenerator::hash($token));
        if ($stored === null || $stored->type === TokenType::Refresh) {
            return new ValidationFailure('The access token is invalid.');
        }
        if ($stored->type === TokenType::Personal && !$this->personalTokens) {
            return new ValidationFailure('Personal access tokens are disabled.');
        }
        if ($stored->revokedAt !== null) {
            return new ValidationFailure('The access token was revoked.');
        }
        if ($stored->isExpired($now)) {
            return new ValidationFailure('The access token expired.');
        }
        if ($stored->resource !== $target->identifier) {
            return new ValidationFailure('The access token was issued for another resource.');
        }
        $client = null;
        if ($stored->clientInternalId !== null) {
            $client = $this->clients->findClientById($stored->clientInternalId);
            if ($client === null || $client->isRevoked()) {
                return new ValidationFailure('The client of this access token was revoked.');
            }
        }
        $owner = match (true) {
            $stored->subjectType === SubjectType::User => $this->users->findBySubject($stored->subject),
            $client !== null => $this->users->forClient($client, $target),
            default => null,
        };
        if ($owner === null) {
            return new ValidationFailure('The owner of this access token no longer has access.');
        }
        $scopes = $this->scopes->effective(
            $target,
            $stored->scopes,
            $client?->scopes,
            $this->users->scopesFor($owner, $target),
        );
        if ($scopes === []) {
            return new ValidationFailure('The token no longer grants any scope.');
        }
        $idle = $stored->lastUsedAt === null ? null : $now->getTimestamp() - $stored->lastUsedAt->getTimestamp();
        if ($touch && ($idle === null || $idle >= $this->touchInterval)) {
            // Best effort: recording a use must never fail the request being authorized.
            try {
                $this->tokens->touchToken($stored->id, $now);
                if ($client !== null) {
                    $this->clients->touchClient($client->id, $now);
                }
            } catch (Throwable) {
                // Ignored on purpose; the next request tries again.
            }
        }

        return new ValidatedToken($stored, $owner, $client, $target, $scopes);
    }
}
