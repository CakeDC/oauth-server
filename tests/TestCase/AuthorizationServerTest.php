<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase;

use CakeDC\OAuth\Server\AuthorizationServer;
use CakeDC\OAuth\Server\Storage\InMemory\InMemoryStorage;
use CakeDC\OAuth\Server\Test\Support\FakeUserContext;
use CakeDC\OAuth\Server\Test\Support\FakeUsers;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use Nyholm\Psr7\Factory\Psr17Factory;
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
}
