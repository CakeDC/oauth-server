<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Client;

use CakeDC\OAuth\Server\Event\ClientRegistered;
use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Resource\ResourceRegistry;
use CakeDC\OAuth\Server\Scope\Scopes;
use CakeDC\OAuth\Server\Storage\ClientRepositoryInterface;
use CakeDC\OAuth\Server\Support\Uuid;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use InvalidArgumentException;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Registers clients: dynamically (RFC 7591) or by hand.
 */
final class ClientRegistrar
{
    private const MAX_REDIRECT_URIS = 10;

    /**
     * @param \CakeDC\OAuth\Server\Storage\ClientRepositoryInterface $clients Storage.
     * @param \CakeDC\OAuth\Server\Token\TokenGenerator $generator Ids and secrets.
     * @param \Psr\Clock\ClockInterface $clock Clock.
     * @param \CakeDC\OAuth\Server\Resource\ResourceRegistry $resources Known scopes.
     * @param \Psr\EventDispatcher\EventDispatcherInterface $events Events.
     * @param bool $allowPrivateSchemes Native clients may use private-use URI schemes.
     */
    public function __construct(
        private readonly ClientRepositoryInterface $clients,
        private readonly TokenGenerator $generator,
        private readonly ClockInterface $clock,
        private readonly ResourceRegistry $resources,
        private readonly EventDispatcherInterface $events,
        private readonly bool $allowPrivateSchemes = true,
    ) {
    }

    /**
     * Registers a client from RFC 7591 metadata.
     *
     * @param array<mixed> $metadata The registration request.
     * @return array{client: \CakeDC\OAuth\Server\Client\Client, secret: string|null}
     * @throws \CakeDC\OAuth\Server\Exception\OAuthException invalid_client_metadata or invalid_redirect_uri.
     */
    public function register(array $metadata): array
    {
        $applicationType = ApplicationType::tryFrom(self::optionalString($metadata, 'application_type') ?? 'web');
        if ($applicationType === null) {
            throw OAuthException::invalidClientMetadata('application_type must be "web" or "native".');
        }
        $redirectUris = $metadata['redirect_uris'] ?? null;
        if (!is_array($redirectUris) || $redirectUris === [] || !array_is_list($redirectUris)) {
            throw OAuthException::invalidRedirectUri('redirect_uris must list at least one URI.');
        }
        if (count($redirectUris) > self::MAX_REDIRECT_URIS) {
            throw OAuthException::invalidRedirectUri(
                sprintf('Register at most %d redirect_uris.', self::MAX_REDIRECT_URIS),
            );
        }
        foreach ($redirectUris as $index => $uri) {
            $error = is_string($uri)
                ? RedirectUriMatcher::registrationError($uri, $applicationType, $this->allowPrivateSchemes)
                : 'must be a string';
            if ($error !== null) {
                throw OAuthException::invalidRedirectUri(sprintf('redirect_uris[%d] %s.', $index, $error));
            }
        }
        $method = ClientAuthMethod::tryFrom(
            self::optionalString($metadata, 'token_endpoint_auth_method') ?? ClientAuthMethod::SecretBasic->value,
        );
        if ($method === null) {
            throw OAuthException::invalidClientMetadata(
                'token_endpoint_auth_method must be "none", "client_secret_basic" or "client_secret_post".',
            );
        }
        $grantTypes = self::stringList($metadata, 'grant_types') ?? [GrantType::AUTHORIZATION_CODE];
        if (in_array(GrantType::CLIENT_CREDENTIALS, $grantTypes, true)) {
            throw OAuthException::invalidClientMetadata(
                'client_credentials clients are registered by an administrator.',
            );
        }
        foreach ($grantTypes as $grantType) {
            if (!in_array($grantType, [GrantType::AUTHORIZATION_CODE, GrantType::REFRESH_TOKEN], true)) {
                throw OAuthException::invalidClientMetadata(
                    sprintf('The grant type "%s" is not supported.', $grantType),
                );
            }
        }
        if (!in_array(GrantType::AUTHORIZATION_CODE, $grantTypes, true)) {
            throw OAuthException::invalidClientMetadata('grant_types must include authorization_code.');
        }
        $responseTypes = self::stringList($metadata, 'response_types') ?? ['code'];
        if ($responseTypes !== ['code']) {
            throw OAuthException::invalidClientMetadata('response_types must be ["code"].');
        }
        $name = self::optionalString($metadata, 'client_name');
        if ($name !== null && (strlen($name) > 255 || !ClientMetadata::isUsableName($name))) {
            throw OAuthException::invalidClientMetadata(
                'client_name must have 1 to 255 characters, without control characters.',
            );
        }
        $scopes = null;
        $scope = self::optionalString($metadata, 'scope');
        if ($scope !== null) {
            try {
                $scopes = Scopes::parse($scope);
            } catch (OAuthException $e) {
                throw OAuthException::invalidClientMetadata($e->getMessage());
            }
            // offline_access is not a resource scope: it is requested per authorization, never stored.
            $scopes = array_values(array_diff($scopes, [Scopes::OFFLINE_ACCESS]));
            $known = $this->resources->allScopeNames();
            foreach ($scopes as $one) {
                if (!in_array($one, $known, true)) {
                    throw OAuthException::invalidClientMetadata(sprintf('The scope "%s" does not exist.', $one));
                }
            }
        }
        /** @var list<string> $redirectUris */
        $host = (string)parse_url($redirectUris[0], PHP_URL_HOST);
        $secret = $method === ClientAuthMethod::None ? null : $this->generator->clientSecret();
        $client = new Client(
            id: Uuid::v4(),
            clientId: $this->generator->clientId(),
            type: ClientType::Dynamic,
            applicationType: $applicationType,
            name: $name !== null ? trim($name) : ($host !== '' ? $host : 'Unnamed client'),
            redirectUris: $redirectUris,
            grantTypes: $grantTypes,
            authMethod: $method,
            createdAt: $this->clock->now(),
            secretHash: $secret === null ? null : TokenGenerator::hash($secret),
            scopes: $scopes,
            clientUri: self::optionalHttpsUrl($metadata, 'client_uri'),
            logoUri: self::optionalHttpsUrl($metadata, 'logo_uri'),
            metadata: self::storableMetadata($metadata),
        );
        $this->clients->saveClient($client);
        $this->events->dispatch(new ClientRegistered($client));

        return ['client' => $client, 'secret' => $secret];
    }

    /**
     * Registers a client by hand, for example from a command.
     *
     * @param string $name Display name.
     * @param array<mixed> $redirectUris Redirect URIs (strings); may be empty for client credentials only.
     * @param bool $confidential Whether it gets a secret.
     * @param list<string> $grantTypes Grant types.
     * @param list<string>|null $scopes Allowed scopes; null for any.
     * @param bool $allowIntrospection May call the introspection endpoint.
     * @param \CakeDC\OAuth\Server\Client\ApplicationType $applicationType Web or native.
     * @return array{client: \CakeDC\OAuth\Server\Client\Client, secret: string|null}
     * @throws \InvalidArgumentException
     */
    public function create(
        string $name,
        array $redirectUris,
        bool $confidential,
        array $grantTypes = [GrantType::AUTHORIZATION_CODE, GrantType::REFRESH_TOKEN],
        ?array $scopes = null,
        bool $allowIntrospection = false,
        ApplicationType $applicationType = ApplicationType::Web,
    ): array {
        if (strlen($name) > 255 || !ClientMetadata::isUsableName($name)) {
            throw new InvalidArgumentException('The name must have 1 to 255 characters, without control characters.');
        }
        if ($scopes !== null) {
            $known = $this->resources->allScopeNames();
            foreach ($scopes as $one) {
                if (!in_array($one, $known, true)) {
                    throw new InvalidArgumentException(sprintf('The scope "%s" does not exist.', $one));
                }
            }
        }
        if (count($redirectUris) > self::MAX_REDIRECT_URIS) {
            throw new InvalidArgumentException(
                sprintf('Register at most %d redirect URIs.', self::MAX_REDIRECT_URIS),
            );
        }
        foreach ($grantTypes as $grantType) {
            $known = [GrantType::AUTHORIZATION_CODE, GrantType::REFRESH_TOKEN, GrantType::CLIENT_CREDENTIALS];
            if (!in_array($grantType, $known, true)) {
                throw new InvalidArgumentException(sprintf('Unknown grant type "%s".', $grantType));
            }
        }
        if (!$confidential && (in_array(GrantType::CLIENT_CREDENTIALS, $grantTypes, true) || $allowIntrospection)) {
            throw new InvalidArgumentException('Client credentials and introspection need a confidential client.');
        }
        if (in_array(GrantType::AUTHORIZATION_CODE, $grantTypes, true) && $redirectUris === []) {
            throw new InvalidArgumentException('The authorization code grant needs at least one redirect URI.');
        }
        $uris = [];
        foreach ($redirectUris as $uri) {
            if (!is_string($uri)) {
                throw new InvalidArgumentException('Every redirect URI must be a string.');
            }
            $error = RedirectUriMatcher::registrationError($uri, $applicationType, true);
            if ($error !== null) {
                throw new InvalidArgumentException(sprintf('The redirect URI "%s" %s.', $uri, $error));
            }
            $uris[] = $uri;
        }
        $secret = $confidential ? $this->generator->clientSecret() : null;
        $client = new Client(
            id: Uuid::v4(),
            clientId: $this->generator->clientId(),
            type: ClientType::Registered,
            applicationType: $applicationType,
            name: trim($name),
            redirectUris: $uris,
            grantTypes: $grantTypes,
            authMethod: $confidential ? ClientAuthMethod::SecretBasic : ClientAuthMethod::None,
            createdAt: $this->clock->now(),
            secretHash: $secret === null ? null : TokenGenerator::hash($secret),
            scopes: $scopes,
            allowIntrospection: $allowIntrospection,
        );
        $this->clients->saveClient($client);
        $this->events->dispatch(new ClientRegistered($client));

        return ['client' => $client, 'secret' => $secret];
    }

    /**
     * The RFC 7591 registration response body.
     *
     * @return array<string, mixed>
     */
    public static function registrationResponse(Client $client, ?string $secret): array
    {
        $body = [
            'client_id' => $client->clientId,
            'client_id_issued_at' => $client->createdAt->getTimestamp(),
            'client_name' => $client->name,
            'redirect_uris' => $client->redirectUris,
            'grant_types' => $client->grantTypes,
            'response_types' => ['code'],
            'token_endpoint_auth_method' => $client->authMethod->value,
            'application_type' => $client->applicationType->value,
        ];
        if ($secret !== null) {
            $body['client_secret'] = $secret;
            $body['client_secret_expires_at'] = 0;
        }
        if ($client->scopes !== null) {
            $body['scope'] = Scopes::format($client->scopes);
        }
        if ($client->clientUri !== null) {
            $body['client_uri'] = $client->clientUri;
        }
        if ($client->logoUri !== null) {
            $body['logo_uri'] = $client->logoUri;
        }

        return $body;
    }

    /**
     * A string member, or null when absent.
     *
     * @param array<mixed> $metadata Metadata.
     * @throws \CakeDC\OAuth\Server\Exception\OAuthException
     */
    private static function optionalString(array $metadata, string $key): ?string
    {
        $value = $metadata[$key] ?? null;
        if ($value !== null && !is_string($value)) {
            throw OAuthException::invalidClientMetadata(sprintf('%s must be a string.', $key));
        }

        return $value;
    }

    /**
     * A list of strings, or null when absent.
     *
     * @param array<mixed> $metadata Metadata.
     * @return list<string>|null
     * @throws \CakeDC\OAuth\Server\Exception\OAuthException
     */
    private static function stringList(array $metadata, string $key): ?array
    {
        $value = $metadata[$key] ?? null;
        if ($value === null) {
            return null;
        }
        if (!is_array($value) || !array_is_list($value) || array_filter($value, 'is_string') !== $value) {
            throw OAuthException::invalidClientMetadata(sprintf('%s must be a list of strings.', $key));
        }

        /** @var list<string> $value */
        return $value;
    }

    /**
     * An https URL member, or null when absent.
     *
     * @param array<mixed> $metadata Metadata.
     * @throws \CakeDC\OAuth\Server\Exception\OAuthException
     */
    private static function optionalHttpsUrl(array $metadata, string $key): ?string
    {
        $value = self::optionalString($metadata, $key);
        if ($value !== null && !ClientMetadata::isPublicHttpsUrl($value)) {
            throw OAuthException::invalidClientMetadata(sprintf('%s must be an https URL.', $key));
        }

        return $value;
    }

    /**
     * The metadata with string keys, for storage, without members the server issues itself.
     *
     * @param array<mixed> $metadata Metadata.
     * @return array<string, mixed>
     */
    private static function storableMetadata(array $metadata): array
    {
        $issued = [
            'client_id', 'client_secret', 'client_id_issued_at', 'client_secret_expires_at',
            'registration_access_token',
        ];
        $result = [];
        foreach ($metadata as $key => $value) {
            if (!in_array((string)$key, $issued, true)) {
                $result[(string)$key] = $value;
            }
        }

        return $result;
    }
}
