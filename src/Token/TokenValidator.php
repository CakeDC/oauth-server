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

/**
 * Validates access and personal tokens presented to a protected resource.
 */
final class TokenValidator
{
    /**
     * @param \CakeDC\OAuth\Server\Storage\TokenRepositoryInterface $tokens Token storage.
     * @param \CakeDC\OAuth\Server\Storage\ClientRepositoryInterface $clients Client storage.
     * @param \CakeDC\OAuth\Server\Owner\UserProviderInterface $users The application's people.
     * @param \CakeDC\OAuth\Server\Resource\ResourceRegistry $resources Resources.
     * @param \CakeDC\OAuth\Server\Scope\ScopeResolver $scopes Scopes.
     * @param \Psr\Clock\ClockInterface $clock Clock.
     * @param int $touchInterval Least seconds between two `last_used_at` updates.
     */
    public function __construct(
        private readonly TokenRepositoryInterface $tokens,
        private readonly ClientRepositoryInterface $clients,
        private readonly UserProviderInterface $users,
        private readonly ResourceRegistry $resources,
        private readonly ScopeResolver $scopes,
        private readonly ClockInterface $clock,
        private readonly int $touchInterval = 60,
    ) {
    }

    /**
     * Checks $token presented to $resource.
     *
     * @throws \InvalidArgumentException When $resource is not declared (a configuration error).
     */
    public function validate(string $token, string $resource): ValidatedToken|ValidationFailure
    {
        $target = $this->resources->get($resource);
        if ($target === null) {
            throw new InvalidArgumentException(sprintf('The resource "%s" is not declared.', $resource));
        }
        $now = $this->clock->now();
        $stored = $this->tokens->findTokenByHash(TokenGenerator::hash($token));
        if ($stored === null || $stored->type === TokenType::Refresh) {
            return new ValidationFailure('The access token is invalid.');
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
        $idle = $stored->lastUsedAt === null ? null : $now->getTimestamp() - $stored->lastUsedAt->getTimestamp();
        if ($idle === null || $idle >= $this->touchInterval) {
            $this->tokens->touchToken($stored->id, $now);
            if ($client !== null) {
                $this->clients->touchClient($client->id, $now);
            }
        }

        return new ValidatedToken($stored, $owner, $client, $target, $scopes);
    }
}
