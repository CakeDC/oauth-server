<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase;

use CakeDC\OAuth\Server\View\Messages;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class DocsTest extends TestCase
{
    private static function docs(): string
    {
        $root = dirname(__DIR__, 2);
        $text = (string)file_get_contents($root . '/README.md');
        foreach (glob($root . '/docs/*.md') ?: [] as $file) {
            $text .= "\n" . file_get_contents($file);
        }

        return $text;
    }

    /**
     * @return array<string, array{string}>
     */
    public static function mustBeDocumented(): array
    {
        $items = [
            // Configuration keys (ServerConfig::fromArray).
            'issuer', 'secret', 'resources', 'defaultResource', 'routePrefix', 'tokenPrefix', 'lifetimes',
            'refreshTokens', 'registration', 'cimd', 'clientCredentials', 'introspection', 'personalTokens',
            'connections', 'rateLimit', 'retentionDays', 'refreshReuseGrace', 'personalMax', 'initialAccessToken',
            'allowPrivateSchemes', 'allowedHosts', 'maxBytes', 'cacheMin', 'cacheMax', 'defaultScopes', 'implies',
            // Error codes.
            'invalid_request', 'invalid_client', 'invalid_grant', 'unauthorized_client', 'unsupported_grant_type',
            'unsupported_response_type', 'invalid_scope', 'invalid_target', 'access_denied',
            'invalid_client_metadata', 'invalid_redirect_uri', 'invalid_token', 'server_error',
            'temporarily_unavailable', 'insufficient_scope',
            // Events and the reasons they carry.
            'TokenIssued', 'TokenRevoked', 'ConsentGranted', 'ClientRegistered', 'RefreshTokenReused',
            'AuthorizationDenied', 'not_allowed', 'user_denied', 'code_reuse', 'refresh_reuse', 'grace',
            'rotation_revoked', 'client_revoked', 'issue_failed', 'connection',
            // Endpoints and entry points.
            '/.well-known/oauth-authorization-server', '/authorize', '/token', '/register', '/revoke',
            '/introspect', '/connections', 'BearerTokenMiddleware', 'mcpTokenValidator', 'PdoStorage',
            'StorageContractTestCase', 'UserProviderInterface', 'UserContextInterface', 'Pruner',
            // Classes and options that users touch.
            'AuthorizationServer', 'ServerConfig', 'ClientRegistrar', 'TokenRevoker', 'TokenValidator',
            'ValidatedToken', 'ConnectionService', 'createPersonalToken', 'InMemoryStorage', 'StorageInterface',
            'ConsentRendererInterface', 'ConnectionsRendererInterface', 'ErrorPageRendererInterface', 'Messages',
            'RequestPath', 'HostName', 'ClientIp', 'allowIntrospection', 'offline_access', 'consent_token',
            'form_token', 'decision', 'family_id', 'token_id', 'create_token', 'revoke_connection',
            'revoke_token', 'bearerMiddleware', 'forClient', 'scopesFor', 'findBySubject', 'canAuthorize',
            'currentOwner', 'loginResponse', 'family_started_at', 'revokeAllForSubject', 'revokeAllForClient',
            'tests/Conformance/run.sh', 'conformance.md',
        ];
        $items = array_merge($items, array_keys(Messages::DEFAULTS));

        return array_combine($items, array_map(fn(string $item): array => [$item], $items));
    }

    #[DataProvider('mustBeDocumented')]
    public function testIsDocumented(string $item): void
    {
        $this->assertStringContainsString($item, self::docs());
    }

    /**
     * @return array<string, array{string}>
     */
    public static function pages(): array
    {
        $pages = [];
        foreach (glob(dirname(__DIR__, 2) . '/docs/*.md') ?: [] as $file) {
            $pages[basename($file)] = [basename($file)];
        }

        return $pages;
    }

    #[DataProvider('pages')]
    public function testEveryPageIsLinkedFromTheReadmeAndTheIndex(string $page): void
    {
        $root = dirname(__DIR__, 2);
        $this->assertStringContainsString('docs/' . $page, (string)file_get_contents($root . '/README.md'));
        if ($page !== 'index.md') {
            $this->assertStringContainsString('(' . $page . ')', (string)file_get_contents($root . '/docs/index.md'));
        }
    }

    public function testEveryExpectedPageExists(): void
    {
        $expected = [
            'index', 'concepts', 'installation', 'configuration', 'users', 'storage', 'endpoints', 'errors',
            'protecting-resources', 'mcp', 'frameworks', 'clients', 'pages', 'personal-tokens', 'events',
            'security', 'deployment', 'operations', 'troubleshooting', 'conformance',
        ];
        foreach ($expected as $page) {
            $this->assertFileExists(dirname(__DIR__, 2) . '/docs/' . $page . '.md');
        }
    }

    public function testNoEmDashes(): void
    {
        $this->assertStringNotContainsString("\u{2014}", self::docs());
        $this->assertStringNotContainsString("\u{2014}", (string)file_get_contents(dirname(__DIR__, 2) . '/CHANGELOG.md'));
    }

    public function testNoEnDashes(): void
    {
        $this->assertStringNotContainsString("\u{2013}", self::docs());
    }
}
