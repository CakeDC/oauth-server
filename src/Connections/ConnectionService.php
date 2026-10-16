<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Connections;

use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Owner\UserProviderInterface;
use CakeDC\OAuth\Server\Resource\ResourceRegistry;
use CakeDC\OAuth\Server\Storage\ClientRepositoryInterface;
use CakeDC\OAuth\Server\Storage\ConsentRepositoryInterface;
use CakeDC\OAuth\Server\Storage\TokenRepositoryInterface;
use CakeDC\OAuth\Server\Support\Time;
use CakeDC\OAuth\Server\Token\Token;
use CakeDC\OAuth\Server\Token\TokenIssuer;
use CakeDC\OAuth\Server\Token\TokenRevoker;
use CakeDC\OAuth\Server\Token\TokenType;
use Psr\Clock\ClockInterface;

/**
 * What an owner sees and manages on the connections page.
 */
final class ConnectionService
{
    /**
     * @param \CakeDC\OAuth\Server\Storage\TokenRepositoryInterface $tokens Tokens.
     * @param \CakeDC\OAuth\Server\Storage\ClientRepositoryInterface $clients Clients.
     * @param \CakeDC\OAuth\Server\Storage\ConsentRepositoryInterface $consents Consents.
     * @param \CakeDC\OAuth\Server\Token\TokenIssuer $issuer Issuer.
     * @param \CakeDC\OAuth\Server\Token\TokenRevoker $revoker Revoker.
     * @param \CakeDC\OAuth\Server\Resource\ResourceRegistry $resources Resources.
     * @param \CakeDC\OAuth\Server\Owner\UserProviderInterface $users People.
     * @param \Psr\Clock\ClockInterface $clock Clock.
     * @param int $personalMaxSeconds Longest life of a personal token.
     */
    public function __construct(
        private readonly TokenRepositoryInterface $tokens,
        private readonly ClientRepositoryInterface $clients,
        private readonly ConsentRepositoryInterface $consents,
        private readonly TokenIssuer $issuer,
        private readonly TokenRevoker $revoker,
        private readonly ResourceRegistry $resources,
        private readonly UserProviderInterface $users,
        private readonly ClockInterface $clock,
        private readonly int $personalMaxSeconds = 7776000,
    ) {
    }

    /**
     * The owner's live client connections, one per family, newest first.
     *
     * @return list<\CakeDC\OAuth\Server\Connections\Connection>
     */
    public function connections(ResourceOwner $owner): array
    {
        $families = [];
        $active = $this->tokens->findActiveTokensBySubject($owner->subject, $owner->type, $this->clock->now());
        foreach ($active as $token) {
            if ($token->type !== TokenType::Personal && $token->clientInternalId !== null) {
                $families[$token->familyId][] = $token;
            }
        }
        $connections = [];
        foreach ($families as $familyId => $live) {
            $client = $this->clients->findClientById((string)$live[0]->clientInternalId);
            if ($client === null || $client->isRevoked()) {
                continue;
            }
            $all = $this->tokens->findTokensByFamily((string)$familyId);
            $lastUsed = null;
            foreach ($all as $token) {
                if ($token->lastUsedAt !== null && ($lastUsed === null || $token->lastUsedAt > $lastUsed)) {
                    $lastUsed = $token->lastUsedAt;
                }
            }
            $newest = $live[count($live) - 1];
            $connectedAt = $newest->familyStartedAt ?? $newest->createdAt;
            foreach ($all as $token) {
                $started = $token->familyStartedAt ?? $token->createdAt;
                if ($started < $connectedAt) {
                    $connectedAt = $started;
                }
            }
            $connections[] = new Connection(
                (string)$familyId,
                $client,
                $newest->resource,
                $newest->scopes,
                $connectedAt,
                $lastUsed,
            );
        }
        usort($connections, fn(Connection $a, Connection $b): int => $b->connectedAt <=> $a->connectedAt);

        return $connections;
    }

    /**
     * The owner's live personal tokens, oldest first.
     *
     * @return list<\CakeDC\OAuth\Server\Token\Token>
     */
    public function personalTokens(ResourceOwner $owner): array
    {
        return array_values(array_filter(
            $this->tokens->findActiveTokensBySubject($owner->subject, $owner->type, $this->clock->now()),
            fn(Token $token): bool => $token->type === TokenType::Personal,
        ));
    }

    /**
     * Resources and scopes the owner may put in a personal token.
     *
     * @return array<string, array{name: string, scopes: array<string, string>}>
     */
    public function creatableScopes(ResourceOwner $owner): array
    {
        $creatable = [];
        foreach ($this->resources->all() as $resource) {
            $allowed = $resource->expand($this->users->scopesFor($owner, $resource) ?? $resource->scopeNames());
            $scopes = array_filter(
                $resource->scopes,
                fn(string $scope): bool => in_array($scope, $allowed, true),
                ARRAY_FILTER_USE_KEY,
            );
            if ($scopes !== []) {
                $creatable[$resource->identifier] = ['name' => $resource->name, 'scopes' => $scopes];
            }
        }

        return $creatable;
    }

    /**
     * Longest a personal token may live, in days.
     */
    public function maxPersonalDays(): int
    {
        return max(1, intdiv($this->personalMaxSeconds, 86400));
    }

    /**
     * Creates a personal token; its value is returned once and never stored.
     *
     * @param \CakeDC\OAuth\Server\Owner\ResourceOwner $owner Owner.
     * @param string $name A name for the owner to recognise it.
     * @param string $resource Resource identifier.
     * @param list<string> $scopes Scopes.
     * @param int $days Days until it expires.
     * @return array{token: \CakeDC\OAuth\Server\Token\Token, value: string}
     * @throws \CakeDC\OAuth\Server\Exception\OAuthException
     */
    public function createPersonalToken(
        ResourceOwner $owner,
        string $name,
        string $resource,
        array $scopes,
        int $days,
    ): array {
        $name = trim($name);
        if ($name === '' || strlen($name) > 100) {
            throw OAuthException::invalidRequest('Give the token a name of up to 100 characters.');
        }
        $target = $this->resources->get($resource);
        if ($target === null) {
            throw OAuthException::invalidTarget('The resource is unknown.');
        }
        if ($scopes === []) {
            throw OAuthException::invalidScope('Choose at least one permission.');
        }
        $allowed = $this->creatableScopes($owner)[$target->identifier]['scopes'] ?? [];
        foreach ($scopes as $scope) {
            if (!isset($allowed[$scope])) {
                throw OAuthException::invalidScope(sprintf('You cannot grant "%s".', $scope));
            }
        }
        $maxDays = $this->maxPersonalDays();
        if ($days < 1 || $days > $maxDays) {
            throw OAuthException::invalidRequest(sprintf('The token must expire in 1 to %d days.', $maxDays));
        }

        return $this->issuer->issuePersonal(
            $owner->subject,
            $target,
            $scopes,
            $name,
            Time::plus($this->clock->now(), $days * 86400),
        );
    }

    /**
     * Revokes one of the owner's connections and forgets its consent; false when it is not theirs.
     */
    public function revokeConnection(ResourceOwner $owner, string $familyId): bool
    {
        $family = $this->tokens->findTokensByFamily($familyId);
        $first = $family[0] ?? null;
        if ($first === null || $first->type === TokenType::Personal || $first->clientInternalId === null) {
            return false;
        }
        foreach ($family as $token) {
            if ($token->subject !== $owner->subject || $token->subjectType !== $owner->type) {
                return false;
            }
        }
        $this->revoker->revokeFamily($familyId, 'connection', $first);
        $this->consents->deleteConsent($owner->subject, $first->clientInternalId, $first->resource);

        return true;
    }

    /**
     * Revokes one of the owner's personal tokens; false when it is not theirs.
     */
    public function revokePersonalToken(ResourceOwner $owner, string $tokenId): bool
    {
        $token = $this->tokens->findTokenById($tokenId);
        if (
            $token === null
            || $token->type !== TokenType::Personal
            || $token->subject !== $owner->subject
            || $token->subjectType !== SubjectType::User
            || $owner->type !== SubjectType::User
        ) {
            return false;
        }
        $this->revoker->revokeTokens([$token], 'personal', $token);

        return true;
    }
}
