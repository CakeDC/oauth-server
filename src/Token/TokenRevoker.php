<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Token;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Event\TokenRevoked;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Storage\TokenRepositoryInterface;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Revokes tokens.
 */
final class TokenRevoker
{
    /**
     * @param \CakeDC\OAuth\Server\Storage\TokenRepositoryInterface $tokens Storage.
     * @param \Psr\Clock\ClockInterface $clock Clock.
     * @param \Psr\EventDispatcher\EventDispatcherInterface $events Events.
     */
    public function __construct(
        private readonly TokenRepositoryInterface $tokens,
        private readonly ClockInterface $clock,
        private readonly EventDispatcherInterface $events,
    ) {
    }

    /**
     * Revokes a token its client presents (RFC 7009). A refresh token takes its whole family with
     * it; an access token only itself. Unknown tokens and tokens of other clients are ignored.
     */
    public function revokeForClient(Client $client, string $token): void
    {
        $found = $this->tokens->findTokenByHash(TokenGenerator::hash($token));
        if ($found === null || $found->clientInternalId !== $client->id) {
            return;
        }
        if ($found->type === TokenType::Refresh) {
            $this->revokeFamily($found->familyId, 'client', $found);

            return;
        }
        if ($found->revokedAt === null) {
            $this->tokens->revokeToken($found->id, $this->clock->now());
            $this->events->dispatch(new TokenRevoked('client', 1, $found));
        }
    }

    /**
     * Revokes the live tokens of a family.
     */
    public function revokeFamily(string $familyId, string $reason, ?Token $token = null): int
    {
        $count = $this->tokens->revokeTokenFamily($familyId, $this->clock->now());
        if ($count > 0) {
            $this->events->dispatch(new TokenRevoked($reason, $count, $token, $familyId));
        }

        return $count;
    }

    /**
     * Revokes the given tokens that are not revoked yet and announces them in one event.
     *
     * @param list<\CakeDC\OAuth\Server\Token\Token> $tokens The tokens.
     * @param string $reason The event reason.
     * @param \CakeDC\OAuth\Server\Token\Token|null $token The token named in the request, if any.
     * @return int How many tokens this call revoked.
     */
    public function revokeTokens(array $tokens, string $reason, ?Token $token = null): int
    {
        $count = 0;
        $now = $this->clock->now();
        foreach ($tokens as $candidate) {
            if ($this->tokens->findTokenById($candidate->id)?->revokedAt !== null) {
                continue;
            }
            $this->tokens->revokeToken($candidate->id, $now);
            $count++;
        }
        if ($count > 0) {
            $this->events->dispatch(new TokenRevoked($reason, $count, $token, $token?->familyId));
        }

        return $count;
    }

    /**
     * Revokes every live token of a subject, for example after a password change.
     */
    public function revokeAllForSubject(string $subject, SubjectType $type = SubjectType::User): int
    {
        $count = $this->tokens->revokeTokensBySubject($subject, $type, $this->clock->now());
        if ($count > 0) {
            $this->events->dispatch(new TokenRevoked('subject', $count, subject: $subject));
        }

        return $count;
    }

    /**
     * Revokes every live token of a client.
     */
    public function revokeAllForClient(Client $client): int
    {
        $count = $this->tokens->revokeTokensByClient($client->id, $this->clock->now());
        if ($count > 0) {
            $this->events->dispatch(new TokenRevoked('client_revoked', $count, clientInternalId: $client->id));
        }

        return $count;
    }
}
