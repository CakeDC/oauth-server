<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase;

use CakeDC\OAuth\Server\AuthorizationServer;
use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Storage\InMemory\InMemoryStorage;
use CakeDC\OAuth\Server\Test\Support\FakeDns;
use CakeDC\OAuth\Server\Test\Support\FakeTransport;
use CakeDC\OAuth\Server\Test\Support\FakeUserContext;
use CakeDC\OAuth\Server\Test\Support\FakeUsers;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\TestCase;

class AuthorizationServerTest extends TestCase
{
    public function testServicesAreSharedInstances(): void
    {
        $server = (new ServerHarness())->server;

        $this->assertSame($server->tokenIssuer(), $server->tokenIssuer());
        $this->assertSame($server->clientResolver(), $server->clientResolver());
        $this->assertSame('https://example.com', $server->config()->issuer);
    }

    #[RequiresPhpExtension('curl')]
    public function testBuildsWithDefaultsWhenCurlIsAvailable(): void
    {
        $factory = new Psr17Factory();
        $server = new AuthorizationServer(
            Fixtures::config(),
            new InMemoryStorage(),
            new FakeUsers(),
            new FakeUserContext(),
            $factory,
            $factory,
        );

        $request = $factory->createServerRequest('GET', '/');
        $this->assertSame(200, $server->metadataHandler()->handle($request)->getStatusCode());
    }

    public function testPrivateSchemesCanBeRefusedEverywhere(): void
    {
        $harness = new ServerHarness(['registration' => ['allowPrivateSchemes' => false]]);
        $meta = ['application_type' => 'native', 'redirect_uris' => ['cursor://anysphere.cursor/oauth']];

        try {
            $harness->server->clientRegistrar()->register($meta);
            $this->fail('Registered');
        } catch (OAuthException $e) {
            $this->assertSame('invalid_redirect_uri', $e->error);
        }

        $url = 'https://claude.ai/oauth/native';
        $harness->transport->serve($url, ['client_id' => $url, 'client_name' => 'Native'] + $meta);
        try {
            $harness->server->clientResolver()->resolve($url);
            $this->fail('Resolved a document with a private scheme.');
        } catch (OAuthException $e) {
            $this->assertSame('invalid_client', $e->error);
            $this->assertStringContainsString('no usable redirect_uris', $e->getMessage());
        }
    }

    public function testDisabledCimdNeverFetches(): void
    {
        $dns = new FakeDns();
        $transport = new FakeTransport();
        $factory = new Psr17Factory();
        $server = new AuthorizationServer(
            Fixtures::config(['cimd' => ['enabled' => false]]),
            new InMemoryStorage(),
            new FakeUsers(),
            new FakeUserContext(),
            $factory,
            $factory,
            transport: $transport,
            dns: $dns,
        );

        $this->assertNull($server->clientResolver()->resolve('https://client.example/x.json'));
        $this->assertSame([], $transport->requests);
    }

    public function testNoCacheMeansNoRateLimiting(): void
    {
        $factory = new Psr17Factory();
        $server = new AuthorizationServer(
            Fixtures::config(['cimd' => ['enabled' => false]]),
            new InMemoryStorage(),
            new FakeUsers(),
            new FakeUserContext(),
            $factory,
            $factory,
        );

        for ($i = 0; $i < 500; $i++) {
            $server->rateLimiter()->hit('token', '203.0.113.7');
        }
        $this->addToAssertionCount(1);
    }

    public function testIssuerWithAPathPublishesRfc8414Locations(): void
    {
        $harness = new ServerHarness(['issuer' => 'https://example.com/tenant']);
        $config = $harness->server->config();

        $document = $harness->json($harness->server->metadataHandler()->handle($harness->request('GET', '/')));

        $this->assertSame('https://example.com/tenant', $document['issuer']);
        $this->assertSame('https://example.com/tenant/oauth/authorize', $document['authorization_endpoint']);
        $this->assertSame('https://example.com/tenant/oauth/token', $document['token_endpoint']);
        $this->assertSame('/.well-known/oauth-authorization-server/tenant', $config->metadataPath());
        $this->assertSame(
            'https://example.com/.well-known/oauth-authorization-server/tenant',
            $config->metadataUrl(),
        );
    }
}
