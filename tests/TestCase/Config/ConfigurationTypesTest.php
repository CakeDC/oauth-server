<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Config;

use CakeDC\OAuth\Server\Config\Lifetimes;
use CakeDC\OAuth\Server\Config\ServerConfig;
use CakeDC\OAuth\Server\Resource\ProtectedResource;
use CakeDC\OAuth\Server\Resource\ResourceRegistry;
use ErrorException;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use stdClass;
use Throwable;

/**
 * Configuration often comes from a framework's config files: a wrongly typed value must be refused with
 * an InvalidArgumentException that names the setting, never a TypeError, an Error or a PHP warning.
 */
class ConfigurationTypesTest extends TestCase
{
    private const MCP = 'https://example.com/mcp';

    /**
     * @return array<string, mixed>
     */
    private static function valid(): array
    {
        return [
            'issuer' => 'https://example.com',
            'secret' => str_repeat('s', 32),
            'resources' => [
                self::MCP => [
                    'name' => 'Example MCP',
                    'scopes' => ['read' => 'Read', 'write' => 'Write'],
                    'implies' => ['write' => ['read']],
                    'defaultScopes' => ['read'],
                ],
            ],
        ];
    }

    /**
     * Setting path => [kind, text the message must contain].
     *
     * @return array<string, array{0: list<string>, 1: string, 2: string}>
     */
    private static function settings(): array
    {
        $resource = ['resources', self::MCP];

        return [
            'issuer' => [['issuer'], 'string', '"issuer"'],
            'secret' => [['secret'], 'string', '"secret"'],
            'resources' => [['resources'], 'map', '"resources"'],
            'defaultResource' => [['defaultResource'], 'string', '"defaultResource"'],
            'routePrefix' => [['routePrefix'], 'string', '"routePrefix"'],
            'tokenPrefix' => [['tokenPrefix'], 'string', '"tokenPrefix"'],
            'refreshTokens' => [['refreshTokens'], 'string', '"refreshTokens"'],
            'lifetimes' => [['lifetimes'], 'map', '"lifetimes"'],
            'lifetimes.code' => [['lifetimes', 'code'], 'int', '"lifetimes.code"'],
            'lifetimes.refreshReuseGrace' => [['lifetimes', 'refreshReuseGrace'], 'int', '"lifetimes.refreshReuseGrace"'],
            'registration' => [['registration'], 'map', '"registration"'],
            'registration.mode' => [['registration', 'mode'], 'string', '"registration.mode"'],
            'registration.initialAccessToken' => [['registration', 'initialAccessToken'], 'string', '"registration.initialAccessToken"'],
            'registration.allowPrivateSchemes' => [['registration', 'allowPrivateSchemes'], 'bool', '"registration.allowPrivateSchemes"'],
            'cimd' => [['cimd'], 'map', '"cimd"'],
            'cimd.enabled' => [['cimd', 'enabled'], 'bool', '"cimd.enabled"'],
            'cimd.allowedHosts' => [['cimd', 'allowedHosts'], 'list', '"cimd.allowedHosts"'],
            'cimd.timeout' => [['cimd', 'timeout'], 'int', '"cimd.timeout"'],
            'cimd.maxBytes' => [['cimd', 'maxBytes'], 'int', '"cimd.maxBytes"'],
            'cimd.cacheMin' => [['cimd', 'cacheMin'], 'int', '"cimd.cacheMin"'],
            'cimd.cacheMax' => [['cimd', 'cacheMax'], 'int', '"cimd.cacheMax"'],
            'clientCredentials' => [['clientCredentials'], 'bool', '"clientCredentials"'],
            'introspection' => [['introspection'], 'bool', '"introspection"'],
            'personalTokens' => [['personalTokens'], 'bool', '"personalTokens"'],
            'connections' => [['connections'], 'bool', '"connections"'],
            'rateLimit' => [['rateLimit'], 'map', '"rateLimit"'],
            'rateLimit.authorize' => [['rateLimit', 'authorize'], 'pair', '"rateLimit.authorize"'],
            'rateLimit.token' => [['rateLimit', 'token'], 'pair', '"rateLimit.token"'],
            'rateLimit.register' => [['rateLimit', 'register'], 'pair', '"rateLimit.register"'],
            'rateLimit.cimd' => [['rateLimit', 'cimd'], 'pair', '"rateLimit.cimd"'],
            'rateLimit.introspect' => [['rateLimit', 'introspect'], 'pair', '"rateLimit.introspect"'],
            'retentionDays' => [['retentionDays'], 'int', '"retentionDays"'],
            'a resource' => [$resource, 'resource', self::MCP],
            'resource name' => [[...$resource, 'name'], 'string', '"name" of the resource "' . self::MCP . '"'],
            'resource scopes' => [[...$resource, 'scopes'], 'map', '"scopes" of the resource "' . self::MCP . '"'],
            'a scope description' => [[...$resource, 'scopes', 'read'], 'string', '"scopes" of the resource "' . self::MCP . '"'],
            'resource implies' => [[...$resource, 'implies'], 'map', '"implies" of the resource "' . self::MCP . '"'],
            'an implied list' => [[...$resource, 'implies', 'write'], 'list', '"implies" of the resource "' . self::MCP . '"'],
            'resource defaultScopes' => [[...$resource, 'defaultScopes'], 'list', '"defaultScopes" of the resource "' . self::MCP . '"'],
        ];
    }

    /**
     * Values of the wrong type for each kind of setting (null means "the default" for most settings).
     *
     * @return array<string, list<mixed>>
     */
    private static function wrongValues(): array
    {
        $object = new stdClass();

        return [
            'string' => [1, 1.5, true, false, [], ['a'], $object],
            'bool' => [1, 0, 'true', 1.5, [], $object],
            'int' => ['5', 5.0, true, [], [5], $object],
            'map' => ['x', 1, true, 1.5, $object],
            'list' => ['x', 1, true, $object, [1], [[]], [$object], [null]],
            'pair' => ['x', 5, [5], [5, '60'], [5, 6, 7], ['max' => 5, 'window' => 6], [5.0, 60], $object],
            'resource' => ['Example MCP', 1, true, null, $object],
        ];
    }

    /**
     * @return array<string, array{list<string>, mixed, string}>
     */
    public static function wronglyTypedSettings(): array
    {
        $cases = [];
        $wrong = self::wrongValues();
        foreach (self::settings() as $name => [$path, $kind, $named]) {
            foreach ($wrong[$kind] as $index => $value) {
                $label = is_object($value) ? 'object' : get_debug_type($value) . ' ' . json_encode($value);
                $cases[$name . ' = ' . $label . ' #' . $index] = [$path, $value, $named];
            }
        }

        return $cases;
    }

    /**
     * @param list<string> $path Where the value goes.
     * @param mixed $value The wrongly typed value.
     * @param string $named What the message must name.
     */
    #[DataProvider('wronglyTypedSettings')]
    public function testServerConfigRefusesAWronglyTypedSettingByName(array $path, mixed $value, string $named): void
    {
        $config = self::valid();
        $cursor = &$config;
        foreach ($path as $key) {
            if (!isset($cursor[$key]) || !is_array($cursor[$key])) {
                $cursor[$key] = [];
            }
            $cursor = &$cursor[$key];
        }
        $cursor = $value;
        unset($cursor);

        $error = $this->failureOf(fn() => ServerConfig::fromArray($config));

        $this->assertInstanceOf(InvalidArgumentException::class, $error, 'No InvalidArgumentException.');
        $this->assertStringContainsString($named, $error->getMessage());
    }

    public function testAResourceGivenAsANameIsRefusedByName(): void
    {
        $error = $this->failureOf(fn() => ResourceRegistry::fromArray([self::MCP => 'Example MCP']));

        $this->assertInstanceOf(InvalidArgumentException::class, $error);
        $this->assertStringContainsString(self::MCP, $error->getMessage());
    }

    public function testAListOfResourceUrlsIsRefusedByPosition(): void
    {
        $error = $this->failureOf(fn() => ResourceRegistry::fromArray([self::MCP]));

        $this->assertInstanceOf(InvalidArgumentException::class, $error);
        $this->assertStringContainsString('"0"', $error->getMessage());
    }

    public function testProtectedResourceRefusesWronglyTypedSettingsByName(): void
    {
        $settings = ['name' => 1, 'scopes' => 'read', 'implies' => 'read', 'defaultScopes' => 'read'];
        foreach ($settings as $key => $value) {
            $error = $this->failureOf(fn() => ProtectedResource::fromArray(
                self::MCP,
                [$key => $value] + ['scopes' => ['read' => 'Read']],
            ));

            $this->assertInstanceOf(InvalidArgumentException::class, $error, $key);
            $this->assertStringContainsString('"' . $key . '"', $error->getMessage());
        }
    }

    public function testLifetimesRefuseWronglyTypedValuesByName(): void
    {
        foreach (['5', 5.0, true, [], null, new stdClass()] as $value) {
            $error = $this->failureOf(fn() => Lifetimes::fromArray(['access' => $value]));

            $this->assertInstanceOf(InvalidArgumentException::class, $error);
            $this->assertStringContainsString('access', $error->getMessage());
        }
    }

    /**
     * What $build throws, with PHP warnings and notices turned into exceptions so they count as failures.
     */
    private function failureOf(callable $build): ?Throwable
    {
        set_error_handler(static function (int $severity, string $message, string $file, int $line): bool {
            throw new ErrorException($message, 0, $severity, $file, $line);
        });
        try {
            $build();
        } catch (Throwable $e) {
            return $e;
        } finally {
            restore_error_handler();
        }

        return null;
    }
}
