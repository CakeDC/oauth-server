<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Client;

use CakeDC\OAuth\Server\Client\ApplicationType;
use CakeDC\OAuth\Server\Client\ClientAuthMethod;
use CakeDC\OAuth\Server\Client\ClientRegistrar;
use CakeDC\OAuth\Server\Client\ClientType;
use CakeDC\OAuth\Server\Event\ClientRegistered;
use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Storage\InMemory\InMemoryStorage;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\RecordingEventDispatcher;
use CakeDC\OAuth\Server\Testing\FrozenClock;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class ClientRegistrarTest extends TestCase
{
    private InMemoryStorage $storage;

    private RecordingEventDispatcher $events;

    private ClientRegistrar $registrar;

    protected function setUp(): void
    {
        $this->storage = new InMemoryStorage();
        $this->events = new RecordingEventDispatcher();
        $this->registrar = new ClientRegistrar(
            $this->storage,
            new TokenGenerator('test'),
            new FrozenClock(),
            Fixtures::resources(),
            $this->events,
        );
    }

    public function testRegistersAPublicClientLikeClaudeDoes(): void
    {
        $result = $this->registrar->register([
            'client_name' => 'Claude',
            'redirect_uris' => ['https://claude.ai/api/mcp/auth_callback'],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
        ]);

        $client = $result['client'];
        $this->assertNull($result['secret']);
        $this->assertSame(ClientType::Dynamic, $client->type);
        $this->assertSame(ApplicationType::Web, $client->applicationType);
        $this->assertTrue($client->isPublic());
        $this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $client->clientId);
        $this->assertSame($client->id, $this->storage->findClientByClientId($client->clientId)?->id);
        $this->assertCount(1, $this->events->ofType(ClientRegistered::class));

        $body = ClientRegistrar::registrationResponse($client, null);
        $this->assertSame($client->clientId, $body['client_id']);
        $this->assertSame(1767225600, $body['client_id_issued_at']);
        $this->assertSame('none', $body['token_endpoint_auth_method']);
        $this->assertSame(['code'], $body['response_types']);
        $this->assertArrayNotHasKey('client_secret', $body);
    }

    public function testDefaultsToAConfidentialClientWithASecret(): void
    {
        $result = $this->registrar->register(['redirect_uris' => ['https://app.example.com/cb']]);

        $this->assertSame(ClientAuthMethod::SecretBasic, $result['client']->authMethod);
        $this->assertNotNull($result['secret']);
        $this->assertStringStartsWith('test_cs_', $result['secret']);
        $this->assertSame(TokenGenerator::hash($result['secret']), $result['client']->secretHash);
        $this->assertSame('app.example.com', $result['client']->name);
        $this->assertSame(['authorization_code'], $result['client']->grantTypes);

        $body = ClientRegistrar::registrationResponse($result['client'], $result['secret']);
        $this->assertSame($result['secret'], $body['client_secret']);
        $this->assertSame(0, $body['client_secret_expires_at']);
    }

    public function testNativeClientsMayUseLoopbackAndPrivateSchemes(): void
    {
        $result = $this->registrar(true)->register([
            'application_type' => 'native',
            'redirect_uris' => ['http://127.0.0.1/callback', 'com.example.app:/oauth'],
            'token_endpoint_auth_method' => 'none',
            'scope' => 'content:read api',
        ]);

        $this->assertSame(ApplicationType::Native, $result['client']->applicationType);
        $this->assertSame(['content:read', 'api'], $result['client']->scopes);
    }

    /**
     * @return array<string, array{array<string, mixed>, string, string}>
     */
    public static function invalid(): array
    {
        $ok = ['redirect_uris' => ['https://app.example.com/cb']];

        return [
            'no redirect' => [[], 'invalid_redirect_uri', 'redirect_uris'],
            'web private scheme' => [
                ['application_type' => 'web', 'redirect_uris' => ['cursor://x/cb']],
                'invalid_redirect_uri',
                'redirect_uris[0]',
            ],
            'remote http' => [['redirect_uris' => ['http://app.example.com/cb']], 'invalid_redirect_uri', 'http'],
            // RFC 9700 section 2.6 and the spec: loopback http is for native clients.
            'web loopback http' => [
                ['application_type' => 'web', 'redirect_uris' => ['https://app.example.com/cb', 'http://127.0.0.1:1234/cb']],
                'invalid_redirect_uri',
                'redirect_uris[1]',
            ],
            'explicit web loopback http' => [
                ['application_type' => 'web', 'redirect_uris' => ['http://localhost/cb']],
                'invalid_redirect_uri',
                'native',
            ],
            'native private scheme by default' => [
                ['application_type' => 'native', 'redirect_uris' => ['com.example.app:/cb']],
                'invalid_redirect_uri',
                'not allowed',
            ],
            'too many' => [['redirect_uris' => array_fill(0, 11, 'https://a.example/cb')], 'invalid_redirect_uri', '10'],
            'bad app type' => [$ok + ['application_type' => 'tv'], 'invalid_client_metadata', 'application_type'],
            'client credentials' => [$ok + ['grant_types' => ['client_credentials']], 'invalid_client_metadata', 'client_credentials'],
            'no code grant' => [$ok + ['grant_types' => ['refresh_token']], 'invalid_client_metadata', 'authorization_code'],
            'implicit' => [$ok + ['response_types' => ['token']], 'invalid_client_metadata', 'response_types'],
            'bad method' => [$ok + ['token_endpoint_auth_method' => 'private_key_jwt'], 'invalid_client_metadata', 'token_endpoint_auth_method'],
            'unknown scope' => [$ok + ['scope' => 'admin'], 'invalid_client_metadata', 'admin'],
            'http logo' => [$ok + ['logo_uri' => 'http://app.example.com/logo.png'], 'invalid_client_metadata', 'logo_uri'],
            'control chars' => [$ok + ['client_name' => "Evil\nApp"], 'invalid_client_metadata', 'client_name'],
            'scope syntax' => [$ok + ['scope' => 'a"b'], 'invalid_client_metadata', 'scope'],
            'blank logo host' => [$ok + ['logo_uri' => 'https://'], 'invalid_client_metadata', 'logo_uri'],
            'encoded client_uri host' => [$ok + ['client_uri' => 'https://%65xample.com'], 'invalid_client_metadata', 'client_uri'],
            'long name' => [$ok + ['client_name' => str_repeat('n', 256)], 'invalid_client_metadata', 'client_name'],
        ];
    }

    #[DataProvider('invalid')]
    public function testRejectsInvalidMetadata(array $metadata, string $error, string $message): void
    {
        try {
            $this->registrar->register($metadata);
            $this->fail('Registered');
        } catch (OAuthException $e) {
            $this->assertSame($error, $e->error);
            $this->assertStringContainsString($message, $e->getMessage());
        }
        $this->assertSame([], $this->storage->findClients());
    }

    public function testCreatesRegisteredClientsByHand(): void
    {
        $result = $this->registrar->create(
            'Reporting job',
            [],
            true,
            ['client_credentials'],
            ['api'],
            true,
        );

        $client = $result['client'];
        $this->assertSame(ClientType::Registered, $client->type);
        $this->assertTrue($client->allowsGrant('client_credentials'));
        $this->assertTrue($client->allowIntrospection);
        $this->assertNotNull($result['secret']);
    }

    public function testHandMadeClientsFollowTheSameRules(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('confidential');

        $this->registrar->create('Bad', ['https://a.example/cb'], false, ['client_credentials']);
    }

    public function testOfflineAccessIsNotStoredAsAClientScope(): void
    {
        $result = $this->registrar->register([
            'redirect_uris' => ['https://app.example.com/cb'],
            'scope' => 'content:read offline_access',
        ]);

        $this->assertSame(['content:read'], $result['client']->scopes);
    }

    public function testSuppliedCredentialsAreIgnoredAndNotStored(): void
    {
        $result = $this->registrar->register([
            'redirect_uris' => ['https://app.example.com/cb'],
            'client_id' => 'chosen',
            'client_secret' => 'chosen-secret',
            'client_id_issued_at' => 1,
            'registration_access_token' => 'x',
        ]);

        $client = $result['client'];
        $this->assertNotSame('chosen', $client->clientId);
        $this->assertNotSame(TokenGenerator::hash('chosen-secret'), $client->secretHash);
        $this->assertSame(['redirect_uris' => ['https://app.example.com/cb']], $client->metadata);
    }

    public function testRegistersClientSecretPost(): void
    {
        $result = $this->registrar->register([
            'redirect_uris' => ['https://app.example.com/cb'],
            'token_endpoint_auth_method' => 'client_secret_post',
        ]);

        $this->assertSame(ClientAuthMethod::SecretPost, $result['client']->authMethod);
        $this->assertNotNull($result['secret']);
    }

    /**
     * @return array<string, array{array<string, mixed>, string}>
     */
    public static function invalidCreate(): array
    {
        return [
            'unknown scope' => [['name' => 'A', 'scopes' => ['admin']], 'admin'],
            'control chars' => [['name' => "A\nB"], 'control'],
            'too many uris' => [['name' => 'A', 'uris' => array_fill(0, 11, 'https://a.example/cb')], 'at most 10'],
            'non string uri' => [['name' => 'A', 'uris' => [42]], 'string'],
        ];
    }

    /**
     * @param array<string, mixed> $args
     */
    #[DataProvider('invalidCreate')]
    public function testCreateFollowsTheRegistrationRules(array $args, string $message): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        $this->registrar->create($args['name'], $args['uris'] ?? ['https://a.example/cb'], true, scopes: $args['scopes'] ?? null);
    }

    public function testCreateAllowsPrivateSchemesForNativeAdminClients(): void
    {
        $result = $this->registrar->create(
            'Desktop',
            ['cursor://anysphere.cursor/oauth', 'myapp:/oauth'],
            false,
            applicationType: ApplicationType::Native,
        );

        $this->assertSame(['cursor://anysphere.cursor/oauth', 'myapp:/oauth'], $result['client']->redirectUris);
    }

    public function testCreateStillAcceptsLoopbackHttpForWebClients(): void
    {
        // The web-only rule is about self-registration; an administrator chooses on purpose.
        $result = $this->registrar->create('Local tool', ['http://127.0.0.1/callback'], false);

        $this->assertSame(['http://127.0.0.1/callback'], $result['client']->redirectUris);
    }

    public function testPrivateSchemesAreRefusedForNativeRegistrationsByDefault(): void
    {
        try {
            $this->registrar->register(['application_type' => 'native', 'redirect_uris' => ['com.example.app:/oauth']]);
            $this->fail('Registered');
        } catch (OAuthException $e) {
            $this->assertSame('invalid_redirect_uri', $e->error);
            $this->assertStringContainsString('not allowed', $e->getMessage());
        }
        $this->assertSame([], $this->storage->findClients());
    }

    public function testEnabledPrivateSchemesAcceptAnySchemeThatIsNotDangerous(): void
    {
        $registrar = $this->registrar(true);

        foreach (['cursor://anysphere.cursor/oauth', 'myapp:/cb', 'com.example.app:/cb'] as $uri) {
            $result = $registrar->register(['application_type' => 'native', 'redirect_uris' => [$uri]]);
            $this->assertSame([$uri], $result['client']->redirectUris, $uri);
        }
        try {
            $registrar->register(['application_type' => 'native', 'redirect_uris' => ['javascript:alert(1)']]);
            $this->fail('Registered a javascript: URI');
        } catch (OAuthException $e) {
            $this->assertSame('invalid_redirect_uri', $e->error);
        }
    }

    public function testLoopbackOnlyRegistrationsWithoutApplicationTypeAreNative(): void
    {
        // What MCP clients (Inspector, VS Code, Claude Code's fallback) send.
        $result = $this->registrar->register([
            'client_name' => 'MCP Inspector',
            'redirect_uris' => ['http://localhost:6274/oauth/callback', 'http://127.0.0.1/callback'],
            'token_endpoint_auth_method' => 'none',
        ]);

        $this->assertSame(ApplicationType::Native, $result['client']->applicationType);
        $this->assertSame('native', ClientRegistrar::registrationResponse($result['client'], null)['application_type']);
    }

    public function testPrivateSchemeRegistrationsWithoutApplicationTypeAreNative(): void
    {
        $result = $this->registrar(true)->register([
            'client_name' => 'Cursor',
            'redirect_uris' => ['cursor://anysphere.cursor/oauth', 'http://127.0.0.1/callback'],
            'token_endpoint_auth_method' => 'none',
        ]);

        $this->assertSame(ApplicationType::Native, $result['client']->applicationType);
    }

    public function testMixedRegistrationsWithoutApplicationTypeStayWebAndKeepLoopback(): void
    {
        $result = $this->registrar->register([
            'redirect_uris' => ['https://app.example.com/cb', 'http://127.0.0.1/cb'],
        ]);

        $this->assertSame(ApplicationType::Web, $result['client']->applicationType);
        $this->assertSame(['https://app.example.com/cb', 'http://127.0.0.1/cb'], $result['client']->redirectUris);
    }

    public function testNativeClientsMayRegisterLoopbackHttp(): void
    {
        $result = $this->registrar->register([
            'application_type' => 'native',
            'redirect_uris' => ['http://127.0.0.1:1234/cb'],
            'token_endpoint_auth_method' => 'none',
        ]);

        $this->assertSame(['http://127.0.0.1:1234/cb'], $result['client']->redirectUris);
    }

    private function registrar(bool $allowPrivateSchemes): ClientRegistrar
    {
        return new ClientRegistrar(
            $this->storage,
            new TokenGenerator('test'),
            new FrozenClock(),
            Fixtures::resources(),
            $this->events,
            $allowPrivateSchemes,
        );
    }
}
