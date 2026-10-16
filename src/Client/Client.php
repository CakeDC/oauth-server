<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Client;

use CakeDC\OAuth\Server\Support\HostClass;
use DateTimeImmutable;

/**
 * An OAuth client: registered by hand, registered dynamically, or described by a metadata document.
 */
final class Client
{
    /**
     * @param string $id Internal UUID; foreign keys point here.
     * @param string $clientId The public OAuth `client_id`; a URL for metadata document clients.
     * @param \CakeDC\OAuth\Server\Client\ClientType $type Origin.
     * @param \CakeDC\OAuth\Server\Client\ApplicationType $applicationType Web or native.
     * @param string $name Display name.
     * @param list<string> $redirectUris Registered redirect URIs.
     * @param list<string> $grantTypes Grant types it may use.
     * @param \CakeDC\OAuth\Server\Client\ClientAuthMethod $authMethod Token endpoint authentication.
     * @param \DateTimeImmutable $createdAt Creation time.
     * @param string|null $secretHash SHA-256 of the secret, for confidential clients.
     * @param list<string>|null $scopes Scopes it may get; null for any.
     * @param string|null $clientUri Home page.
     * @param string|null $logoUri Logo.
     * @param bool $allowIntrospection May call the introspection endpoint.
     * @param array<string, mixed>|null $metadata The registration request or metadata document.
     * @param \DateTimeImmutable|null $metadataFetchedAt When the metadata document was fetched.
     * @param \DateTimeImmutable|null $metadataExpiresAt When to fetch it again.
     * @param \DateTimeImmutable|null $lastUsedAt Last token request or use.
     * @param \DateTimeImmutable|null $revokedAt When it was revoked.
     */
    public function __construct(
        public readonly string $id,
        public readonly string $clientId,
        public readonly ClientType $type,
        public readonly ApplicationType $applicationType,
        public readonly string $name,
        public readonly array $redirectUris,
        public readonly array $grantTypes,
        public readonly ClientAuthMethod $authMethod,
        public readonly DateTimeImmutable $createdAt,
        public readonly ?string $secretHash = null,
        public readonly ?array $scopes = null,
        public readonly ?string $clientUri = null,
        public readonly ?string $logoUri = null,
        public readonly bool $allowIntrospection = false,
        public readonly ?array $metadata = null,
        public readonly ?DateTimeImmutable $metadataFetchedAt = null,
        public readonly ?DateTimeImmutable $metadataExpiresAt = null,
        public readonly ?DateTimeImmutable $lastUsedAt = null,
        public readonly ?DateTimeImmutable $revokedAt = null,
    ) {
    }

    /**
     * Whether the client has no secret.
     */
    public function isPublic(): bool
    {
        return $this->authMethod === ClientAuthMethod::None;
    }

    /**
     * Whether the client may use $grantType.
     */
    public function allowsGrant(string $grantType): bool
    {
        return in_array($grantType, $this->grantTypes, true);
    }

    /**
     * Whether the client was revoked.
     */
    public function isRevoked(): bool
    {
        return $this->revokedAt !== null;
    }

    /**
     * The host the consent page names: the `client_id` URL's host for metadata documents (their
     * `client_name` is self-asserted), otherwise the first redirect URI's host.
     */
    public function displayHost(): string
    {
        $url = $this->type === ClientType::MetadataDocument ? $this->clientId : ($this->redirectUris[0] ?? '');
        $host = parse_url($url, PHP_URL_HOST);

        return is_string($host) ? strtolower($host) : '';
    }

    /**
     * Whether every redirect URI stays on this computer (a loopback or unspecified address, a `.localhost`
     * name, or a private-use scheme), where any program can receive the answer.
     */
    public function redirectsOnlyToLoopback(): bool
    {
        foreach ($this->redirectUris as $uri) {
            if (!HostClass::redirectStaysOnThisComputer($uri)) {
                return false;
            }
        }

        return $this->redirectUris !== [];
    }

    /**
     * A copy marked revoked at $at.
     */
    public function withRevokedAt(DateTimeImmutable $at): self
    {
        return $this->copy(['revokedAt' => $at]);
    }

    /**
     * A copy last used at $at.
     */
    public function withLastUsedAt(DateTimeImmutable $at): self
    {
        return $this->copy(['lastUsedAt' => $at]);
    }

    /**
     * A copy with some properties replaced.
     *
     * @param array<string, mixed> $changes Property => value.
     */
    private function copy(array $changes): self
    {
        return new self(...array_merge(get_object_vars($this), $changes));
    }
}
