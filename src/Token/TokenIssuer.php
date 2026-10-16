<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Token;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Config\Lifetimes;
use CakeDC\OAuth\Server\Event\TokenIssued;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Resource\ProtectedResource;
use CakeDC\OAuth\Server\Storage\TokenRepositoryInterface;
use CakeDC\OAuth\Server\Support\Time;
use CakeDC\OAuth\Server\Support\Uuid;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Issues and stores tokens.
 *
 * @internal Built through the AuthorizationServer factories, not by you: get it from the server.
 * Its constructor may change in any 1.x release.
 */
final class TokenIssuer
{
    /**
     * @param \CakeDC\OAuth\Server\Storage\TokenRepositoryInterface $tokens Storage.
     * @param \CakeDC\OAuth\Server\Token\TokenGenerator $generator Secrets.
     * @param \Psr\Clock\ClockInterface $clock Clock.
     * @param \Psr\EventDispatcher\EventDispatcherInterface $events Events.
     * @param \CakeDC\OAuth\Server\Config\Lifetimes $lifetimes Lifetimes.
     */
    public function __construct(
        private readonly TokenRepositoryInterface $tokens,
        private readonly TokenGenerator $generator,
        private readonly ClockInterface $clock,
        private readonly EventDispatcherInterface $events,
        private readonly Lifetimes $lifetimes,
    ) {
    }

    /**
     * Issues an access token and, when asked and the family is young enough, a refresh token.
     *
     * @param \CakeDC\OAuth\Server\Client\Client|null $client The client.
     * @param string $subject Owner subject.
     * @param \CakeDC\OAuth\Server\Owner\SubjectType $subjectType User or client.
     * @param \CakeDC\OAuth\Server\Resource\ProtectedResource $resource The resource.
     * @param list<string> $scopes Granted scopes.
     * @param string $familyId Token family.
     * @param bool $withRefresh Whether to issue a refresh token.
     * @param string|null $parentId The refresh token being rotated.
     * @param \DateTimeImmutable|null $familyStartedAt When the family began; now by default.
     * @param list<string>|null $refreshScopes Scopes of the refresh token when they differ from the access
     *   token's: a refresh keeps the grant while the access token is narrowed. Null: the same as $scopes.
     */
    public function issue(
        ?Client $client,
        string $subject,
        SubjectType $subjectType,
        ProtectedResource $resource,
        array $scopes,
        string $familyId,
        bool $withRefresh,
        ?string $parentId = null,
        ?DateTimeImmutable $familyStartedAt = null,
        ?array $refreshScopes = null,
    ): IssuedTokens {
        $scopes = array_values(array_unique($scopes));
        $refreshScopes = $refreshScopes === null ? $scopes : array_values(array_unique($refreshScopes));
        $now = $this->clock->now();
        $familyStartedAt ??= $now;
        $accessValue = $this->generator->accessToken();
        $access = $this->store(new Token(
            id: Uuid::v4(),
            tokenHash: TokenGenerator::hash($accessValue),
            type: TokenType::Access,
            familyId: $familyId,
            clientInternalId: $client?->id,
            subject: $subject,
            subjectType: $subjectType,
            resource: $resource->identifier,
            scopes: $scopes,
            createdAt: $now,
            expiresAt: Time::plus($now, $this->lifetimes->access),
            parentId: $parentId,
            familyStartedAt: $familyStartedAt,
        ), $client);
        if (!$withRefresh) {
            return new IssuedTokens($access, $accessValue);
        }
        $familyEnd = Time::plus($familyStartedAt, $this->lifetimes->family);
        $refreshEnd = Time::plus($now, $this->lifetimes->refresh);
        $expiresAt = $refreshEnd < $familyEnd ? $refreshEnd : $familyEnd;
        if ($expiresAt <= $now) {
            return new IssuedTokens($access, $accessValue);
        }
        $refreshValue = $this->generator->refreshToken();
        $refresh = $this->store(new Token(
            id: Uuid::v4(),
            tokenHash: TokenGenerator::hash($refreshValue),
            type: TokenType::Refresh,
            familyId: $familyId,
            clientInternalId: $client?->id,
            subject: $subject,
            subjectType: $subjectType,
            resource: $resource->identifier,
            scopes: $refreshScopes,
            createdAt: $now,
            expiresAt: $expiresAt,
            parentId: $parentId,
            familyStartedAt: $familyStartedAt,
        ), $client);

        return new IssuedTokens($access, $accessValue, $refresh, $refreshValue);
    }

    /**
     * Issues a personal access token.
     *
     * @param string $subject Owner subject.
     * @param \CakeDC\OAuth\Server\Resource\ProtectedResource $resource The resource.
     * @param list<string> $scopes Scopes.
     * @param string $name Name the owner gave it.
     * @param \DateTimeImmutable $expiresAt Expiry.
     * @return array{token: \CakeDC\OAuth\Server\Token\Token, value: string}
     */
    public function issuePersonal(
        string $subject,
        ProtectedResource $resource,
        array $scopes,
        string $name,
        DateTimeImmutable $expiresAt,
    ): array {
        $scopes = array_values(array_unique($scopes));
        $value = $this->generator->personalToken();
        $token = $this->store(new Token(
            id: Uuid::v4(),
            tokenHash: TokenGenerator::hash($value),
            type: TokenType::Personal,
            familyId: Uuid::v4(),
            clientInternalId: null,
            subject: $subject,
            subjectType: SubjectType::User,
            resource: $resource->identifier,
            scopes: $scopes,
            createdAt: $this->clock->now(),
            expiresAt: $expiresAt,
            name: $name,
        ), null);

        return ['token' => $token, 'value' => $value];
    }

    /**
     * Saves a token and announces it.
     */
    private function store(Token $token, ?Client $client): Token
    {
        $this->tokens->saveToken($token);
        $this->events->dispatch(new TokenIssued($token, $client));

        return $token;
    }
}
