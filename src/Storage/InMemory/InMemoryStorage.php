<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Storage\InMemory;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Client\ClientType;
use CakeDC\OAuth\Server\Grant\AuthorizationCode;
use CakeDC\OAuth\Server\Grant\Consent;
use CakeDC\OAuth\Server\Maintenance\PruneResult;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Storage\StorageInterface;
use CakeDC\OAuth\Server\Support\Time;
use CakeDC\OAuth\Server\Token\Token;
use DateTimeImmutable;

/**
 * Storage in PHP arrays, for tests and examples. Nothing survives the request.
 */
final class InMemoryStorage implements StorageInterface
{
    /**
     * @var array<string, \CakeDC\OAuth\Server\Client\Client>
     */
    private array $clients = [];

    /**
     * @var array<string, \CakeDC\OAuth\Server\Grant\AuthorizationCode>
     */
    private array $codes = [];

    /**
     * @var array<string, \CakeDC\OAuth\Server\Token\Token>
     */
    private array $tokens = [];

    /**
     * @var array<string, \CakeDC\OAuth\Server\Grant\Consent>
     */
    private array $consents = [];

    /**
     * @inheritDoc
     */
    public function findClientByClientId(string $clientId): ?Client
    {
        foreach ($this->clients as $client) {
            if ($client->clientId === $clientId) {
                return $client;
            }
        }

        return null;
    }

    /**
     * @inheritDoc
     */
    public function findClientById(string $id): ?Client
    {
        return $this->clients[$id] ?? null;
    }

    /**
     * @inheritDoc
     */
    public function saveClient(Client $client): void
    {
        $this->clients[$client->id] = $client;
    }

    /**
     * @inheritDoc
     */
    public function touchClient(string $id, DateTimeImmutable $at): void
    {
        if (isset($this->clients[$id])) {
            $this->clients[$id] = $this->clients[$id]->withLastUsedAt($at);
        }
    }

    /**
     * @inheritDoc
     */
    public function findClients(?ClientType $type = null): array
    {
        $clients = array_values(array_filter(
            $this->clients,
            fn(Client $client): bool => $type === null || $client->type === $type,
        ));
        usort($clients, fn(Client $a, Client $b): int => $a->createdAt <=> $b->createdAt);

        return $clients;
    }

    /**
     * @inheritDoc
     */
    public function saveCode(AuthorizationCode $code): void
    {
        $this->codes[$code->id] = $code;
    }

    /**
     * @inheritDoc
     */
    public function findCodeByHash(string $hash): ?AuthorizationCode
    {
        foreach ($this->codes as $code) {
            if ($code->codeHash === $hash) {
                return $code;
            }
        }

        return null;
    }

    /**
     * @inheritDoc
     */
    public function consumeCode(string $id, DateTimeImmutable $at, string $familyId): bool
    {
        $code = $this->codes[$id] ?? null;
        if ($code === null || $code->usedAt !== null) {
            return false;
        }
        $this->codes[$id] = new AuthorizationCode(
            ...array_merge(get_object_vars($code), ['usedAt' => $at, 'familyId' => $familyId]),
        );

        return true;
    }

    /**
     * @inheritDoc
     */
    public function saveToken(Token $token): void
    {
        $this->tokens[$token->id] = $token;
    }

    /**
     * @inheritDoc
     */
    public function findTokenByHash(string $hash): ?Token
    {
        foreach ($this->tokens as $token) {
            if ($token->tokenHash === $hash) {
                return $token;
            }
        }

        return null;
    }

    /**
     * @inheritDoc
     */
    public function findTokenById(string $id): ?Token
    {
        return $this->tokens[$id] ?? null;
    }

    /**
     * @inheritDoc
     */
    public function markTokenUsed(string $id, DateTimeImmutable $at): bool
    {
        $token = $this->tokens[$id] ?? null;
        if ($token === null || $token->usedAt !== null) {
            return false;
        }
        $this->tokens[$id] = $this->withToken($token, ['usedAt' => $at]);

        return true;
    }

    /**
     * @inheritDoc
     */
    public function revokeToken(string $id, DateTimeImmutable $at): void
    {
        $this->revokeWhere(fn(Token $token): bool => $token->id === $id, $at);
    }

    /**
     * @inheritDoc
     */
    public function revokeTokenFamily(string $familyId, DateTimeImmutable $at): int
    {
        return $this->revokeWhere(fn(Token $token): bool => $token->familyId === $familyId, $at);
    }

    /**
     * @inheritDoc
     */
    public function revokeTokensBySubject(string $subject, SubjectType $type, DateTimeImmutable $at): int
    {
        return $this->revokeWhere(
            fn(Token $token): bool => $token->subject === $subject && $token->subjectType === $type,
            $at,
        );
    }

    /**
     * @inheritDoc
     */
    public function revokeTokensByClient(string $clientInternalId, DateTimeImmutable $at): int
    {
        return $this->revokeWhere(fn(Token $token): bool => $token->clientInternalId === $clientInternalId, $at);
    }

    /**
     * @inheritDoc
     */
    public function findTokensByFamily(string $familyId): array
    {
        return $this->sorted(array_filter($this->tokens, fn(Token $token): bool => $token->familyId === $familyId));
    }

    /**
     * @inheritDoc
     */
    public function findActiveTokensBySubject(string $subject, SubjectType $type, DateTimeImmutable $now): array
    {
        return $this->sorted(array_filter(
            $this->tokens,
            fn(Token $token): bool => $token->subject === $subject
                && $token->subjectType === $type
                && $token->isActive($now),
        ));
    }

    /**
     * @inheritDoc
     */
    public function touchToken(string $id, DateTimeImmutable $at): void
    {
        if (isset($this->tokens[$id])) {
            $this->tokens[$id] = $this->withToken($this->tokens[$id], ['lastUsedAt' => $at]);
        }
    }

    /**
     * @inheritDoc
     */
    public function findConsent(string $subject, string $clientInternalId, string $resource): ?Consent
    {
        return $this->consents[$this->consentKey($subject, $clientInternalId, $resource)] ?? null;
    }

    /**
     * @inheritDoc
     */
    public function saveConsent(Consent $consent): void
    {
        $key = $this->consentKey($consent->subject, $consent->clientInternalId, $consent->resource);
        $existing = $this->consents[$key] ?? null;
        if ($existing !== null) {
            $consent = new Consent(
                $existing->id,
                $consent->subject,
                $consent->clientInternalId,
                $consent->resource,
                $consent->scopes,
                $existing->createdAt,
                $consent->modifiedAt,
            );
        }
        $this->consents[$key] = $consent;
    }

    /**
     * @inheritDoc
     */
    public function deleteConsent(string $subject, string $clientInternalId, string $resource): void
    {
        unset($this->consents[$this->consentKey($subject, $clientInternalId, $resource)]);
    }

    /**
     * @inheritDoc
     */
    public function prune(DateTimeImmutable $now, int $retentionSeconds, int $unusedClientSeconds): PruneResult
    {
        $cutoff = Time::plus($now, -$retentionSeconds);
        $codes = 0;
        foreach ($this->codes as $id => $code) {
            if ($code->expiresAt < $now) {
                unset($this->codes[$id]);
                $codes++;
            }
        }
        $tokens = 0;
        foreach ($this->tokens as $id => $token) {
            $revokedLongAgo = $token->revokedAt !== null && $token->revokedAt < $cutoff;
            $expiredLongAgo = $token->expiresAt !== null && $token->expiresAt < $cutoff;
            if ($revokedLongAgo || $expiredLongAgo) {
                unset($this->tokens[$id]);
                $tokens++;
            }
        }
        $clients = 0;
        $createdCutoff = Time::plus($now, -$unusedClientSeconds);
        foreach ($this->clients as $id => $client) {
            if ($client->type === ClientType::Registered || $client->createdAt >= $createdCutoff) {
                continue;
            }
            if ($client->lastUsedAt !== null && $client->lastUsedAt >= $cutoff) {
                continue;
            }
            foreach ($this->tokens as $token) {
                if ($token->clientInternalId === $id && $token->isActive($now)) {
                    continue 2;
                }
            }
            foreach ($this->tokens as $tokenId => $token) {
                if ($token->clientInternalId === $id) {
                    unset($this->tokens[$tokenId]);
                    $tokens++;
                }
            }
            $this->codes = array_filter($this->codes, fn(AuthorizationCode $c): bool => $c->clientInternalId !== $id);
            $this->consents = array_filter($this->consents, fn(Consent $c): bool => $c->clientInternalId !== $id);
            unset($this->clients[$id]);
            $clients++;
        }

        return new PruneResult($codes, $tokens, $clients);
    }

    /**
     * Revokes the live tokens matching $match.
     *
     * @param callable(\CakeDC\OAuth\Server\Token\Token): bool $match Filter.
     */
    private function revokeWhere(callable $match, DateTimeImmutable $at): int
    {
        $count = 0;
        foreach ($this->tokens as $id => $token) {
            if ($token->revokedAt === null && $match($token)) {
                $this->tokens[$id] = $this->withToken($token, ['revokedAt' => $at]);
                $count++;
            }
        }

        return $count;
    }

    /**
     * A copy of $token with some properties replaced.
     *
     * @param array<string, mixed> $changes Property => value.
     */
    private function withToken(Token $token, array $changes): Token
    {
        return new Token(...array_merge(get_object_vars($token), $changes));
    }

    /**
     * Tokens oldest first.
     *
     * @param array<\CakeDC\OAuth\Server\Token\Token> $tokens Tokens.
     * @return list<\CakeDC\OAuth\Server\Token\Token>
     */
    private function sorted(array $tokens): array
    {
        $tokens = array_values($tokens);
        usort($tokens, fn(Token $a, Token $b): int => $a->createdAt <=> $b->createdAt);

        return $tokens;
    }

    /**
     * The key of a consent.
     */
    private function consentKey(string $subject, string $clientInternalId, string $resource): string
    {
        return $subject . "\n" . $clientInternalId . "\n" . $resource;
    }
}
