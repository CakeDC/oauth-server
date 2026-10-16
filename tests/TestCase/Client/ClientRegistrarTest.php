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
        $result = $this->registrar->register([
            'application_type' => 'native',
            'redirect_uris' => ['http://127.0.0.1/callback', 'cursor://anysphere.cursor/oauth'],
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
            'web private scheme' => [['redirect_uris' => ['cursor://x/cb']], 'invalid_redirect_uri', 'redirect_uris[0]'],
            'remote http' => [['redirect_uris' => ['http://app.example.com/cb']], 'invalid_redirect_uri', 'http'],
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
}
