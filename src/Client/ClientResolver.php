<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Client;

use CakeDC\OAuth\Server\Client\Cimd\MetadataDocumentFetcher;
use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\RateLimit\RateLimiter;
use CakeDC\OAuth\Server\Scope\Scopes;
use CakeDC\OAuth\Server\Storage\ClientRepositoryInterface;
use CakeDC\OAuth\Server\Support\Time;
use CakeDC\OAuth\Server\Support\Uuid;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;
use Psr\SimpleCache\CacheInterface;
use Throwable;

/**
 * Finds the client of a `client_id`: stored clients, and metadata document clients fetched and
 * cached as rows.
 *
 * @internal Built through the AuthorizationServer factories, not by you: get it from the server.
 * Its constructor may change in any 1.x release.
 */
final class ClientResolver
{
    /**
     * Seconds a failed fetch is remembered: a definitive rejection always, a temporary failure only while a
     * stored copy of the client stands in for it.
     */
    private const FAILURE_SECONDS = 60;

    /**
     * @param \CakeDC\OAuth\Server\Storage\ClientRepositoryInterface $clients Storage.
     * @param \Psr\Clock\ClockInterface $clock Clock.
     * @param \CakeDC\OAuth\Server\Client\Cimd\MetadataDocumentFetcher|null $fetcher Null disables metadata documents.
     * @param int $cacheMin Shortest cache time of a document, seconds.
     * @param int $cacheMax Longest cache time of a document, seconds.
     * @param bool $allowPrivateSchemes Native documents may use private-use redirect URI schemes.
     * @param \CakeDC\OAuth\Server\RateLimit\RateLimiter|null $limiter Counts the fetches of one requester
     *   (bucket `cimd`); null does not limit.
     * @param \Psr\SimpleCache\CacheInterface|null $cache Remembers failed fetches for a minute (see
     *   FAILURE_SECONDS); null does not.
     */
    public function __construct(
        private readonly ClientRepositoryInterface $clients,
        private readonly ClockInterface $clock,
        private readonly ?MetadataDocumentFetcher $fetcher = null,
        private readonly int $cacheMin = 300,
        private readonly int $cacheMax = 86400,
        private readonly bool $allowPrivateSchemes = false,
        private readonly ?RateLimiter $limiter = null,
        private readonly ?CacheInterface $cache = null,
    ) {
    }

    /**
     * The client of $clientId, revoked or not; null when unknown.
     *
     * @param string $clientId The client_id.
     * @param string|null $requester Who asks (the client IP). With it, every actual fetch of a metadata
     *   document is counted against the `cimd` rate limit of that requester; cached clients never are.
     * @throws \CakeDC\OAuth\Server\Exception\OAuthException invalid_client when a metadata document cannot be
     *   used, a 429 when the requester is over the fetch budget.
     */
    public function resolve(string $clientId, ?string $requester = null): ?Client
    {
        if ($clientId === '' || strlen($clientId) > 2048) {
            return null;
        }
        if (!MetadataDocumentFetcher::isMetadataDocumentId($clientId)) {
            return $this->clients->findClientByClientId($clientId);
        }
        if ($this->fetcher === null) {
            return null;
        }
        $existing = $this->clients->findClientByClientId($clientId);
        // The host policy is current policy, not history: a cached or revoked row is held to it too.
        if ($existing !== null && !$this->fetcher->allowsClientId($clientId)) {
            throw OAuthException::invalidClient(sprintf(
                'Clients from %s are not accepted.',
                strtolower((string)parse_url($clientId, PHP_URL_HOST)),
            ));
        }
        $now = $this->clock->now();
        $fresh = $existing !== null && $existing->metadataExpiresAt !== null && $existing->metadataExpiresAt > $now;
        if ($existing !== null && ($existing->isRevoked() || $fresh)) {
            return $existing;
        }
        $staleUsable = $existing !== null && $existing->metadataExpiresAt !== null
            && $now < Time::plus($existing->metadataExpiresAt, $this->cacheMax);
        try {
            $fetched = $this->fetchDocument($this->fetcher, $clientId, $requester, $staleUsable);
        } catch (OAuthException $e) {
            if ($e->temporary && $staleUsable) {
                // Stale-if-error, for temporary unavailability only: serve the stored client for a bounded
                // time. Read it back, a revocation may have been committed during the fetch.
                return $this->clients->findClientByClientId($clientId) ?? $existing;
            }

            throw $e;
        }
        try {
            $client = $this->fromDocument($clientId, $fetched['document'], $fetched['maxAge'], $existing, $now);
        } catch (OAuthException $e) {
            $this->rememberFailure($clientId, $e);

            throw $e;
        }
        try {
            $this->clients->saveClient($client);
        } catch (Throwable $e) {
            $stored = $this->clients->findClientByClientId($clientId);
            if ($stored === null || $stored->id === $client->id) {
                throw $e;
            }

            return $stored;
        }

        // Read back: revocation is sticky in storage and may have been committed during the fetch.
        return $this->clients->findClientByClientId($clientId) ?? $client;
    }

    /**
     * Fetches the document, within the requester's budget and the memory of recent failures.
     *
     * A definitive rejection (host policy, address, an invalid document, HTTP 4xx other than 429) is
     * remembered for a minute, so repeating the client_id costs nothing. A temporary failure (network
     * error, timeout, HTTP 5xx or 429) is never remembered as a rejection (the CIMD draft says the server
     * MUST NOT cache error responses), so a new client works as soon as its host answers again. It is
     * remembered only while $staleUsable, where it just keeps the stored copy in service for that minute
     * instead of making every request wait on the same unreachable host and spend its `cimd` budget.
     *
     * @param bool $staleUsable Whether a stored copy may stand in for a temporary failure (stale-if-error).
     * @return array{document: array<string, mixed>, maxAge: int|null}
     * @throws \CakeDC\OAuth\Server\Exception\OAuthException
     */
    private function fetchDocument(
        MetadataDocumentFetcher $fetcher,
        string $clientId,
        ?string $requester,
        bool $staleUsable,
    ): array {
        $remembered = $this->rememberedFailure($clientId);
        if ($remembered !== null && (!$remembered->temporary || $staleUsable)) {
            throw $remembered;
        }
        if ($requester !== null) {
            $this->limiter?->hit('cimd', $requester);
        }
        try {
            return $fetcher->fetch($clientId);
        } catch (OAuthException $e) {
            if (!$e->temporary || $staleUsable) {
                $this->rememberFailure($clientId, $e);
            }

            throw $e;
        }
    }

    /**
     * The cache key of the failure memory of $clientId.
     */
    private static function failureKey(string $clientId): string
    {
        // PSR-16 only guarantees 64 characters: a short prefix and 160 bits of the digest.
        return 'oauth_cf_' . substr(hash('sha256', $clientId), 0, 40);
    }

    /**
     * The failure remembered for $clientId, rebuilt, or null. The cache is best effort.
     */
    private function rememberedFailure(string $clientId): ?OAuthException
    {
        if ($this->cache === null) {
            return null;
        }
        try {
            $stored = $this->cache->get(self::failureKey($clientId));
        } catch (Throwable) {
            return null;
        }
        if (!is_array($stored) || !is_string($stored['message'] ?? null)) {
            return null;
        }

        return ($stored['temporary'] ?? false) === true
            ? OAuthException::clientUnavailable($stored['message'])
            : OAuthException::invalidClient($stored['message']);
    }

    /**
     * Remembers a failed fetch for a minute (see fetchDocument() for which ones).
     */
    private function rememberFailure(string $clientId, OAuthException $failure): void
    {
        if ($this->cache === null || $failure->error !== 'invalid_client') {
            return;
        }
        try {
            $this->cache->set(
                self::failureKey($clientId),
                ['message' => $failure->getMessage(), 'temporary' => $failure->temporary],
                self::FAILURE_SECONDS,
            );
        } catch (Throwable) {
            // Best effort: the failure is simply not remembered.
        }
    }

    /**
     * Builds the client row of a checked metadata document.
     *
     * @param array<string, mixed> $document The document.
     * @throws \CakeDC\OAuth\Server\Exception\OAuthException invalid_client without a usable redirect URI.
     */
    private function fromDocument(
        string $clientId,
        array $document,
        ?int $maxAge,
        ?Client $existing,
        DateTimeImmutable $now,
    ): Client {
        $redirectUris = array_values(array_filter((array)$document['redirect_uris'], 'is_string'));
        $allHttp = $redirectUris !== [] && array_filter(
            $redirectUris,
            fn(string $uri): bool => strtolower((string)parse_url($uri, PHP_URL_SCHEME)) !== 'http',
        ) === [];
        $declared = $document['application_type'] ?? null;
        $applicationType = $declared === 'native' || ($declared === null && $allHttp)
            ? ApplicationType::Native
            : ApplicationType::Web;
        $usable = array_values(array_filter(
            $redirectUris,
            fn(string $uri): bool => RedirectUriMatcher::registrationError(
                $uri,
                $applicationType,
                $this->allowPrivateSchemes,
            ) === null,
        ));
        if ($usable === []) {
            throw OAuthException::invalidClient('The metadata document has no usable redirect_uris.');
        }
        $grantTypes = isset($document['grant_types']) && is_array($document['grant_types'])
            ? array_values(array_filter($document['grant_types'], 'is_string'))
            : [GrantType::AUTHORIZATION_CODE];
        $scopes = null;
        if (isset($document['scope']) && is_string($document['scope'])) {
            try {
                $scopes = Scopes::parse($document['scope']);
            } catch (OAuthException) {
                throw OAuthException::invalidClient('The metadata document has an invalid scope.');
            }
        }
        // PCRE rather than mbstring (not a declared dependency); it fails on invalid UTF-8, then the host is used.
        $name = isset($document['client_name']) && is_string($document['client_name'])
            && preg_match('/\A.{0,255}/su', trim($document['client_name']), $matches) === 1
            ? $matches[0]
            : '';
        if (!ClientMetadata::isUsableName($name)) {
            $host = parse_url($clientId, PHP_URL_HOST);
            $name = is_string($host) ? $host : 'Unnamed client';
        }
        $ttl = max($this->cacheMin, min($this->cacheMax, $maxAge ?? $this->cacheMin));

        return new Client(
            id: $existing->id ?? Uuid::v4(),
            clientId: $clientId,
            type: ClientType::MetadataDocument,
            applicationType: $applicationType,
            name: $name,
            redirectUris: $usable,
            grantTypes: array_values(array_diff($grantTypes, [GrantType::CLIENT_CREDENTIALS])),
            authMethod: ClientAuthMethod::None,
            createdAt: $existing->createdAt ?? $now,
            scopes: $scopes,
            clientUri: self::httpsUrl($document['client_uri'] ?? null),
            logoUri: self::httpsUrl($document['logo_uri'] ?? null),
            metadata: $document,
            metadataFetchedAt: $now,
            metadataExpiresAt: Time::plus($now, $ttl),
            lastUsedAt: $existing?->lastUsedAt,
        );
    }

    /**
     * $value when it is an https URL, else null.
     */
    private static function httpsUrl(mixed $value): ?string
    {
        return is_string($value) && ClientMetadata::isDisplayableHttpsUrl($value) ? $value : null;
    }
}
