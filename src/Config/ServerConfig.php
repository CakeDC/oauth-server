<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Config;

use CakeDC\OAuth\Server\Resource\ResourceIdentifier;
use CakeDC\OAuth\Server\Resource\ResourceRegistry;
use InvalidArgumentException;

/**
 * Settings of the authorization server.
 */
final class ServerConfig
{
    public const REFRESH_ALWAYS = 'always';
    public const REFRESH_OFFLINE_ACCESS = 'offline_access';
    public const REGISTRATION_OPEN = 'open';
    public const REGISTRATION_TOKEN = 'token';
    public const REGISTRATION_CLOSED = 'closed';

    private const DEFAULT_RATE_LIMITS = [
        'authorize' => [30, 60],
        'token' => [60, 60],
        'register' => [10, 3600],
        'cimd' => [10, 60],
    ];

    /**
     * @param string $issuer Canonical issuer URL; https except on loopback hosts.
     * @param \CakeDC\OAuth\Server\Resource\ResourceRegistry $resources What tokens are issued for.
     * @param string $secret At least 32 characters; signs form tokens.
     * @param string $routePrefix Path of the endpoints below the issuer, starting with "/".
     * @param \CakeDC\OAuth\Server\Config\Lifetimes $lifetimes Lifetimes.
     * @param string $tokenPrefix Token prefix.
     * @param string $refreshTokens `always`, or `offline_access` to issue them only when asked.
     * @param string $registrationMode `open`, `token` or `closed`.
     * @param string|null $initialAccessToken Required to register in `token` mode.
     * @param bool $allowPrivateSchemes Native clients may register private-use URI schemes (reverse domain
     *   names such as `com.example.app`). Off by default: MCP requires localhost or https redirect URIs.
     * @param bool $cimdEnabled Accept Client ID Metadata Documents.
     * @param list<string>|null $cimdAllowedHosts Only these client_id hosts; null for any.
     * @param int $cimdTimeout Fetch timeout, seconds.
     * @param int $cimdMaxBytes Largest accepted document.
     * @param int $cimdCacheMin Shortest cache time, seconds.
     * @param int $cimdCacheMax Longest cache time, seconds.
     * @param bool $clientCredentials Enable the client credentials grant.
     * @param bool $introspection Enable the introspection endpoint.
     * @param bool $personalTokens Enable personal access tokens.
     * @param bool $connections Enable the connections page.
     * @param array<string, array{0: int, 1: int}> $rateLimits Endpoint => [max requests, window seconds].
     * @param int $retentionDays How long revoked and expired tokens are kept.
     * @throws \InvalidArgumentException
     */
    public function __construct(
        public readonly string $issuer,
        public readonly ResourceRegistry $resources,
        public readonly string $secret,
        public readonly string $routePrefix = '/oauth',
        public readonly Lifetimes $lifetimes = new Lifetimes(),
        public readonly string $tokenPrefix = 'oauth',
        public readonly string $refreshTokens = self::REFRESH_ALWAYS,
        public readonly string $registrationMode = self::REGISTRATION_OPEN,
        public readonly ?string $initialAccessToken = null,
        public readonly bool $allowPrivateSchemes = false,
        public readonly bool $cimdEnabled = true,
        public readonly ?array $cimdAllowedHosts = null,
        public readonly int $cimdTimeout = 5,
        public readonly int $cimdMaxBytes = 10240,
        public readonly int $cimdCacheMin = 300,
        public readonly int $cimdCacheMax = 86400,
        public readonly bool $clientCredentials = true,
        public readonly bool $introspection = true,
        public readonly bool $personalTokens = true,
        public readonly bool $connections = true,
        public readonly array $rateLimits = self::DEFAULT_RATE_LIMITS,
        public readonly int $retentionDays = 7,
    ) {
        if ($issuer !== ResourceIdentifier::canonicalize($issuer)) {
            throw new InvalidArgumentException(sprintf('The issuer "%s" is not canonical.', $issuer));
        }
        if (parse_url($issuer, PHP_URL_QUERY) !== null) {
            throw new InvalidArgumentException('The issuer must not have a query.');
        }
        ResourceIdentifier::assertSecure($issuer, 'issuer');
        if (strlen($secret) < 32) {
            throw new InvalidArgumentException('The secret must have at least 32 characters.');
        }
        if (preg_match('#^(/[A-Za-z0-9._~-]+)+\z#', $routePrefix) !== 1) {
            throw new InvalidArgumentException(
                '"routePrefix" must start with "/" and not end with "/", like "/oauth".',
            );
        }
        if (!in_array($refreshTokens, [self::REFRESH_ALWAYS, self::REFRESH_OFFLINE_ACCESS], true)) {
            throw new InvalidArgumentException('"refreshTokens" must be "always" or "offline_access".');
        }
        $modes = [self::REGISTRATION_OPEN, self::REGISTRATION_TOKEN, self::REGISTRATION_CLOSED];
        if (!in_array($registrationMode, $modes, true)) {
            throw new InvalidArgumentException('The registration mode must be "open", "token" or "closed".');
        }
        if (
            $registrationMode === self::REGISTRATION_TOKEN
            && ($initialAccessToken === null || $initialAccessToken === '')
        ) {
            throw new InvalidArgumentException('Registration mode "token" needs an "initialAccessToken".');
        }
        $positive = [
            'cimdTimeout' => $cimdTimeout,
            'cimdMaxBytes' => $cimdMaxBytes,
            'cimdCacheMax' => $cimdCacheMax,
            'retentionDays' => $retentionDays,
        ];
        foreach ($positive as $name => $value) {
            if ($value < 1) {
                throw new InvalidArgumentException(sprintf('"%s" must be positive.', $name));
            }
        }
        if ($cimdCacheMin < 0 || $cimdCacheMin > $cimdCacheMax) {
            throw new InvalidArgumentException('"cimdCacheMin" must be between 0 and "cimdCacheMax".');
        }
        foreach ($rateLimits as $endpoint => $limit) {
            if ($limit[0] < 1 || $limit[1] < 1) {
                throw new InvalidArgumentException(
                    sprintf('"rateLimit.%s" must be [max requests, window seconds].', $endpoint),
                );
            }
        }
    }

    /**
     * Builds the settings from an array (see the class docs for the keys).
     *
     * @param array<string, mixed> $config Settings.
     * @throws \InvalidArgumentException
     */
    public static function fromArray(array $config): self
    {
        $known = [
            'issuer', 'secret', 'resources', 'defaultResource', 'routePrefix', 'tokenPrefix', 'lifetimes',
            'refreshTokens', 'registration', 'cimd', 'clientCredentials', 'introspection', 'personalTokens',
            'connections', 'rateLimit', 'retentionDays',
        ];
        $unknown = array_diff(array_keys($config), $known);
        if ($unknown !== []) {
            throw new InvalidArgumentException(
                sprintf('Unknown OAuth server setting "%s".', implode('", "', $unknown)),
            );
        }
        foreach (['issuer', 'secret', 'resources'] as $required) {
            if (!isset($config[$required])) {
                throw new InvalidArgumentException(sprintf('The OAuth server setting "%s" is required.', $required));
            }
        }
        $registration = self::section($config, 'registration', ['mode', 'initialAccessToken', 'allowPrivateSchemes']);
        $cimd = self::section(
            $config,
            'cimd',
            ['enabled', 'allowedHosts', 'timeout', 'maxBytes', 'cacheMin', 'cacheMax'],
        );
        $rateLimit = self::section($config, 'rateLimit', ['authorize', 'token', 'register', 'cimd']);
        $rateLimits = self::DEFAULT_RATE_LIMITS;
        foreach ($rateLimit as $endpoint => $limit) {
            if (
                !is_array($limit)
                || !array_is_list($limit)
                || count($limit) !== 2
                || !is_int($limit[0])
                || !is_int($limit[1])
            ) {
                throw new InvalidArgumentException(
                    sprintf('"rateLimit.%s" must be [max requests, window seconds].', $endpoint),
                );
            }
            $rateLimits[$endpoint] = [$limit[0], $limit[1]];
        }
        $resources = $config['resources'];
        $default = $config['defaultResource'] ?? null;
        if (!is_array($resources) || ($default !== null && !is_string($default))) {
            throw new InvalidArgumentException('"resources" must map resource URLs to settings.');
        }
        $allowedHosts = $cimd['allowedHosts'] ?? null;
        if ($allowedHosts !== null && (!is_array($allowedHosts) || !array_is_list($allowedHosts))) {
            throw new InvalidArgumentException('"cimd.allowedHosts" must be a list of host names.');
        }
        $lifetimes = $config['lifetimes'] ?? [];
        if (!is_array($lifetimes)) {
            throw new InvalidArgumentException('"lifetimes" must be an array.');
        }

        /** @var array<string, array<string, mixed>> $resources */
        /** @var array<string, mixed> $lifetimes */
        return new self(
            issuer: ResourceIdentifier::canonicalize(self::string($config, 'issuer')),
            resources: ResourceRegistry::fromArray($resources, $default),
            secret: self::string($config, 'secret'),
            routePrefix: self::string($config, 'routePrefix', '/oauth'),
            lifetimes: Lifetimes::fromArray($lifetimes),
            tokenPrefix: self::string($config, 'tokenPrefix', 'oauth'),
            refreshTokens: self::string($config, 'refreshTokens', self::REFRESH_ALWAYS),
            registrationMode: self::string($registration, 'mode', self::REGISTRATION_OPEN),
            initialAccessToken: isset($registration['initialAccessToken'])
                ? self::string($registration, 'initialAccessToken')
                : null,
            allowPrivateSchemes: self::bool($registration, 'allowPrivateSchemes', false),
            cimdEnabled: self::bool($cimd, 'enabled', true),
            cimdAllowedHosts: $allowedHosts === null ? null : array_map('strval', $allowedHosts),
            cimdTimeout: self::int($cimd, 'timeout', 5),
            cimdMaxBytes: self::int($cimd, 'maxBytes', 10240),
            cimdCacheMin: self::int($cimd, 'cacheMin', 300),
            cimdCacheMax: self::int($cimd, 'cacheMax', 86400),
            clientCredentials: self::bool($config, 'clientCredentials', true),
            introspection: self::bool($config, 'introspection', true),
            personalTokens: self::bool($config, 'personalTokens', true),
            connections: self::bool($config, 'connections', true),
            rateLimits: $rateLimits,
            retentionDays: self::int($config, 'retentionDays', 7),
        );
    }

    /**
     * Absolute URL of an endpoint: `authorize`, `token`, `register`, `revoke`, `introspect` or `connections`.
     */
    public function endpointUrl(string $endpoint): string
    {
        return $this->issuer . $this->routePrefix . '/' . $endpoint;
    }

    /**
     * Path of an endpoint, for routing.
     */
    public function endpointPath(string $endpoint): string
    {
        return (string)parse_url($this->endpointUrl($endpoint), PHP_URL_PATH);
    }

    /**
     * Path of the RFC 8414 metadata: the well-known segment, then the issuer's path.
     */
    public function metadataPath(): string
    {
        return '/.well-known/oauth-authorization-server' . (string)parse_url($this->issuer, PHP_URL_PATH);
    }

    /**
     * Absolute URL of the RFC 8414 metadata.
     */
    public function metadataUrl(): string
    {
        $path = (string)parse_url($this->issuer, PHP_URL_PATH);
        $origin = $path === '' ? $this->issuer : substr($this->issuer, 0, -strlen($path));

        return $origin . $this->metadataPath();
    }

    /**
     * Whether a code exchange issues a refresh token.
     */
    public function issuesRefreshTokens(bool $offlineAccessRequested): bool
    {
        return $this->refreshTokens === self::REFRESH_ALWAYS || $offlineAccessRequested;
    }

    /**
     * A nested settings array with known keys only.
     *
     * @param array<string, mixed> $config Settings.
     * @param list<string> $known Allowed keys.
     * @return array<string, mixed>
     * @throws \InvalidArgumentException
     */
    private static function section(array $config, string $name, array $known): array
    {
        $section = $config[$name] ?? [];
        if (!is_array($section)) {
            throw new InvalidArgumentException(sprintf('"%s" must be an array.', $name));
        }
        $unknown = array_diff(array_keys($section), $known);
        if ($unknown !== []) {
            throw new InvalidArgumentException(
                sprintf('Unknown setting "%s.%s".', $name, implode('", "' . $name . '.', $unknown)),
            );
        }

        /** @var array<string, mixed> $section */
        return $section;
    }

    /**
     * A string setting.
     *
     * @param array<string, mixed> $config Settings.
     * @throws \InvalidArgumentException
     */
    private static function string(array $config, string $key, ?string $default = null): string
    {
        $value = $config[$key] ?? $default;
        if (!is_string($value)) {
            throw new InvalidArgumentException(sprintf('"%s" must be a string.', $key));
        }

        return $value;
    }

    /**
     * A boolean setting.
     *
     * @param array<string, mixed> $config Settings.
     * @throws \InvalidArgumentException
     */
    private static function bool(array $config, string $key, bool $default): bool
    {
        $value = $config[$key] ?? $default;
        if (!is_bool($value)) {
            throw new InvalidArgumentException(sprintf('"%s" must be true or false.', $key));
        }

        return $value;
    }

    /**
     * An integer setting.
     *
     * @param array<string, mixed> $config Settings.
     * @throws \InvalidArgumentException
     */
    private static function int(array $config, string $key, int $default): int
    {
        $value = $config[$key] ?? $default;
        if (!is_int($value)) {
            throw new InvalidArgumentException(sprintf('"%s" must be an integer.', $key));
        }

        return $value;
    }
}
