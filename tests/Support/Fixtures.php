<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Support;

use CakeDC\OAuth\Server\Client\ApplicationType;
use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Client\ClientAuthMethod;
use CakeDC\OAuth\Server\Client\ClientType;
use CakeDC\OAuth\Server\Config\ServerConfig;
use CakeDC\OAuth\Server\Resource\ResourceRegistry;
use CakeDC\OAuth\Server\Support\Uuid;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use DateTimeImmutable;
use DateTimeZone;

final class Fixtures
{
    public const MCP = 'https://example.com/mcp';
    public const API = 'https://example.com/api';

    /**
     * @return array<string, array<string, mixed>>
     */
    public static function resourceSettings(): array
    {
        return [
            self::MCP => [
                'name' => 'Example MCP',
                'scopes' => [
                    'content:read' => 'Read your posts',
                    'content:write' => 'Edit drafts',
                    'content:publish' => 'Publish posts',
                ],
                'implies' => ['content:publish' => ['content:write'], 'content:write' => ['content:read']],
                'defaultScopes' => ['content:read'],
            ],
            self::API => ['name' => 'Example API', 'scopes' => ['api' => 'Use the API'], 'defaultScopes' => ['api']],
        ];
    }

    public static function resources(): ResourceRegistry
    {
        return ResourceRegistry::fromArray(self::resourceSettings());
    }

    /**
     * @param array<string, mixed> $overrides
     */
    public static function config(array $overrides = []): ServerConfig
    {
        return ServerConfig::fromArray($overrides + [
            'issuer' => 'https://example.com',
            'secret' => str_repeat('k', 32),
            'resources' => self::resourceSettings(),
        ]);
    }

    /**
     * @param array<string, mixed> $overrides Client constructor arguments.
     */
    public static function client(array $overrides = []): Client
    {
        return new Client(...$overrides + [
            'id' => Uuid::v4(),
            'clientId' => 'client-' . bin2hex(random_bytes(4)),
            'type' => ClientType::Dynamic,
            'applicationType' => ApplicationType::Web,
            'name' => 'Test App',
            'redirectUris' => ['https://app.example.com/cb'],
            'grantTypes' => ['authorization_code', 'refresh_token'],
            'authMethod' => ClientAuthMethod::None,
            'createdAt' => new DateTimeImmutable('2026-01-01 00:00:00', new DateTimeZone('UTC')),
        ]);
    }

    /**
     * @param array<string, mixed> $overrides Client constructor arguments.
     */
    public static function confidentialClient(string $secret = 'cs-secret', array $overrides = []): Client
    {
        return self::client($overrides + [
            'type' => ClientType::Registered,
            'authMethod' => ClientAuthMethod::SecretBasic,
            'secretHash' => TokenGenerator::hash($secret),
            'grantTypes' => ['authorization_code', 'refresh_token', 'client_credentials'],
        ]);
    }
}
