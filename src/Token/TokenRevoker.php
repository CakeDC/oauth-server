<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Token;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Event\TokenRevoked;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Storage\AuthorizationCodeRepositoryInterface;
use CakeDC\OAuth\Server\Storage\TokenRepositoryInterface;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Revokes tokens. Revoking everything of a person or of a client also deletes their codes that were not
 * exchanged yet, so a code issued just before cannot open a new family afterwards.
 */
final class TokenRevoker
{
    /**
     * @internal Build it through the AuthorizationServer; its constructor may change in any 1.x release.
     * @param \CakeDC\OAuth\Server\Storage\TokenRepositoryInterface $tokens Storage.
     * @param \CakeDC\OAuth\Server\Storage\AuthorizationCodeRepositoryInterface $codes Codes.
     * @param \Psr\Clock\ClockInterface $clock Clock.
     * @param \Psr\EventDispatcher\EventDispatcherInterface $events Events.
     */
    public function __construct(
        private readonly TokenRepositoryInterface $tokens,
        private readonly AuthorizationCodeRepositoryInterface $codes,
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
     * Revokes every live token of a subject, for example after a password change, and deletes the person's
     * codes that were not exchanged yet. Returns how many tokens it revoked.
     *
     * The codes go first: a code being exchanged at this moment is then either deleted before it is
     * consumed (the exchange fails and revokes what it issued) or consumed with its tokens already
     * stored, so the revocation that follows reaches them.
     */
    public function revokeAllForSubject(string $subject, SubjectType $type = SubjectType::User): int
    {
        if ($type === SubjectType::User) {
            // Codes are only issued to people; a client identity's subject could equal a person's.
            $this->codes->deleteCodesBySubject($subject);
        }
        $count = $this->tokens->revokeTokensBySubject($subject, $type, $this->clock->now());
        if ($count > 0) {
            $this->events->dispatch(new TokenRevoked('subject', $count, subject: $subject));
        }

        return $count;
    }

    /**
     * Revokes every live token of a client and deletes its codes that were not exchanged yet (codes first,
     * as in revokeAllForSubject()). Returns how many tokens it revoked.
     */
    public function revokeAllForClient(Client $client): int
    {
        $this->codes->deleteCodesByClient($client->id);
        $count = $this->tokens->revokeTokensByClient($client->id, $this->clock->now());
        if ($count > 0) {
            $this->events->dispatch(new TokenRevoked('client_revoked', $count, clientInternalId: $client->id));
        }

        return $count;
    }
}
