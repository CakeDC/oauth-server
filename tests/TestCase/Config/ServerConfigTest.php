<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Config;

use CakeDC\OAuth\Server\Config\ServerConfig;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class ServerConfigTest extends TestCase
{
    /**
     * @return array<string, mixed>
     */
    private function minimal(): array
    {
        return [
            'issuer' => 'https://example.com',
            'secret' => str_repeat('s', 32),
            'resources' => ['https://example.com/mcp' => ['scopes' => ['read' => 'Read']]],
        ];
    }

    public function testDefaults(): void
    {
        $config = ServerConfig::fromArray($this->minimal());

        $this->assertSame('https://example.com', $config->issuer);
        $this->assertSame('/oauth', $config->routePrefix);
        $this->assertSame('oauth', $config->tokenPrefix);
        $this->assertSame(ServerConfig::REFRESH_ALWAYS, $config->refreshTokens);
        $this->assertSame(ServerConfig::REGISTRATION_OPEN, $config->registrationMode);
        $this->assertTrue($config->cimdEnabled);
        $this->assertSame(5, $config->cimdTimeout);
        $this->assertSame(
            ['authorize' => [30, 60], 'token' => [60, 60], 'register' => [10, 3600], 'cimd' => [10, 60]],
            $config->rateLimits,
        );
        $this->assertSame(7, $config->retentionDays);
        $this->assertSame('https://example.com/mcp', $config->resources->defaultResource()->identifier);
        // The MCP authorization spec: redirect URIs are localhost or https unless the host opts in.
        $this->assertFalse($config->allowPrivateSchemes);
        $this->assertFalse((new ServerConfig('https://example.com', $config->resources, str_repeat('k', 32)))->allowPrivateSchemes);
    }

    public function testEndpointsHangFromTheIssuer(): void
    {
        $config = ServerConfig::fromArray(['issuer' => 'https://Example.com/app/'] + $this->minimal());

        $this->assertSame('https://example.com/app', $config->issuer);
        $this->assertSame('https://example.com/app/oauth/token', $config->endpointUrl('token'));
        $this->assertSame('/app/oauth/token', $config->endpointPath('token'));
        $this->assertSame('/.well-known/oauth-authorization-server/app', $config->metadataPath());
        $this->assertSame('https://example.com/.well-known/oauth-authorization-server/app', $config->metadataUrl());
    }

    public function testMetadataOfARootIssuer(): void
    {
        $config = ServerConfig::fromArray($this->minimal());

        $this->assertSame('/.well-known/oauth-authorization-server', $config->metadataPath());
        $this->assertSame('/oauth/authorize', $config->endpointPath('authorize'));
    }

    public function testNestedSettings(): void
    {
        $config = ServerConfig::fromArray($this->minimal() + [
            'lifetimes' => ['access' => 900],
            'registration' => ['mode' => 'token', 'initialAccessToken' => 'abc', 'allowPrivateSchemes' => true],
            'cimd' => ['allowedHosts' => ['claude.ai'], 'timeout' => 3],
            'rateLimit' => ['token' => [5, 10], 'cimd' => [3, 30]],
            'refreshTokens' => 'offline_access',
        ]);

        $this->assertSame(900, $config->lifetimes->access);
        $this->assertSame('token', $config->registrationMode);
        $this->assertSame('abc', $config->initialAccessToken);
        $this->assertTrue($config->allowPrivateSchemes);
        $this->assertSame(['claude.ai'], $config->cimdAllowedHosts);
        $this->assertSame(3, $config->cimdTimeout);
        $this->assertSame([5, 10], $config->rateLimits['token']);
        $this->assertSame([30, 60], $config->rateLimits['authorize']);
        $this->assertSame([3, 30], $config->rateLimits['cimd']);
        $this->assertFalse($config->issuesRefreshTokens(false));
        $this->assertTrue($config->issuesRefreshTokens(true));
    }

    /**
     * @return array<string, array{array<string, mixed>, string}>
     */
    public static function invalid(): array
    {
        return [
            'http issuer' => [['issuer' => 'http://example.com'], 'must use https'],
            'issuer with query' => [['issuer' => 'https://example.com?a=1'], 'query'],
            'short secret' => [['secret' => 'short'], '32'],
            'bad prefix' => [['routePrefix' => 'oauth/'], 'routePrefix'],
            'prefix with trailing newline' => [['routePrefix' => "/oauth\n"], 'routePrefix'],
            'bad refresh policy' => [['refreshTokens' => 'sometimes'], 'refreshTokens'],
            'token mode without token' => [['registration' => ['mode' => 'token']], 'initialAccessToken'],
            'unknown key' => [['issuerr' => 'x'], 'issuerr'],
            'bad rate limit' => [['rateLimit' => ['token' => [0, 60]]], 'rateLimit'],
        ];
    }

    /**
     * @param array<string, mixed> $override Settings replacing the minimal ones.
     */
    #[DataProvider('invalid')]
    public function testRejectsInvalidSettings(array $override, string $message): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        ServerConfig::fromArray($override + $this->minimal());
    }

    public function testRequiresIssuerSecretAndResources(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('"issuer"');

        ServerConfig::fromArray(['secret' => str_repeat('s', 32), 'resources' => []]);
    }
}
