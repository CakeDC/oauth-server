<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Client;

use CakeDC\OAuth\Server\Client\Cimd\MetadataDocumentFetcher;
use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Scope\Scopes;
use CakeDC\OAuth\Server\Storage\ClientRepositoryInterface;
use CakeDC\OAuth\Server\Support\Time;
use CakeDC\OAuth\Server\Support\Uuid;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;
use Throwable;

/**
 * Finds the client of a `client_id`: stored clients, and metadata document clients fetched and
 * cached as rows.
 */
final class ClientResolver
{
    /**
     * @param \CakeDC\OAuth\Server\Storage\ClientRepositoryInterface $clients Storage.
     * @param \Psr\Clock\ClockInterface $clock Clock.
     * @param \CakeDC\OAuth\Server\Client\Cimd\MetadataDocumentFetcher|null $fetcher Null disables metadata documents.
     * @param int $cacheMin Shortest cache time of a document, seconds.
     * @param int $cacheMax Longest cache time of a document, seconds.
     * @param bool $allowPrivateSchemes Native documents may use private-use redirect URI schemes.
     */
    public function __construct(
        private readonly ClientRepositoryInterface $clients,
        private readonly ClockInterface $clock,
        private readonly ?MetadataDocumentFetcher $fetcher = null,
        private readonly int $cacheMin = 300,
        private readonly int $cacheMax = 86400,
        private readonly bool $allowPrivateSchemes = true,
    ) {
    }

    /**
     * The client of $clientId, revoked or not; null when unknown.
     *
     * @throws \CakeDC\OAuth\Server\Exception\OAuthException invalid_client when a metadata document cannot be used.
     */
    public function resolve(string $clientId): ?Client
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
        try {
            $fetched = $this->fetcher->fetch($clientId);
        } catch (OAuthException $e) {
            if (
                $e->temporary && $existing !== null && $existing->metadataExpiresAt !== null
                && $now < Time::plus($existing->metadataExpiresAt, $this->cacheMax)
            ) {
                // Stale-if-error, for temporary unavailability only: serve the stored client for a bounded
                // time. Read it back, a revocation may have been committed during the fetch.
                return $this->clients->findClientByClientId($clientId) ?? $existing;
            }

            throw $e;
        }
        $client = $this->fromDocument($clientId, $fetched['document'], $fetched['maxAge'], $existing, $now);
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
