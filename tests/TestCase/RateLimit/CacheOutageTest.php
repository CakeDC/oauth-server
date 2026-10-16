<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\RateLimit;

use CakeDC\OAuth\Server\AuthorizationServer;
use CakeDC\OAuth\Server\Storage\InMemory\InMemoryStorage;
use CakeDC\OAuth\Server\Test\Support\BrokenCache;
use CakeDC\OAuth\Server\Test\Support\FakeDns;
use CakeDC\OAuth\Server\Test\Support\FakeTransport;
use CakeDC\OAuth\Server\Test\Support\FakeUserContext;
use CakeDC\OAuth\Server\Test\Support\FakeUsers;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\RecordingLogger;
use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;

/**
 * With the PSR-16 cache down (Redis gone), the endpoints keep working without rate limits and log a
 * warning, instead of answering 500 to everybody.
 */
class CacheOutageTest extends TestCase
{
    public function testEveryEndpointKeepsWorkingAndWarns(): void
    {
        $factory = new Psr17Factory();
        $storage = new InMemoryStorage();
        $logger = new RecordingLogger();
        $client = Fixtures::client();
        $storage->saveClient($client);
        $server = new AuthorizationServer(
            Fixtures::config(),
            $storage,
            new FakeUsers(),
            new FakeUserContext(),
            $factory,
            $factory,
            cache: new BrokenCache(),
            logger: $logger,
            transport: new FakeTransport(),
            dns: new FakeDns(),
        );
        $request = function (string $method, string $uri, array $headers = [], string $body = ''): ServerRequest {
            return new ServerRequest($method, $uri, $headers, $body, '1.1', ['REMOTE_ADDR' => ServerHarness::IP]);
        };
        $form = ['Content-Type' => 'application/x-www-form-urlencoded'];

        $token = $server->tokenHandler()->handle($request(
            'POST',
            'https://example.com/oauth/token',
            $form,
            'grant_type=refresh_token&refresh_token=nope&client_id=' . rawurlencode($client->clientId),
        ));
        $authorize = $server->authorizeHandler()->handle($request(
            'GET',
            'https://example.com/oauth/authorize?client_id=nobody',
        ));
        $register = $server->registerHandler()->handle($request(
            'POST',
            'https://example.com/oauth/register',
            ['Content-Type' => 'application/json'],
            '{"redirect_uris":["https://app.example.com/cb"],"token_endpoint_auth_method":"none"}',
        ));
        $revoke = $server->revokeHandler()->handle($request(
            'POST',
            'https://example.com/oauth/revoke',
            $form,
            'token=nope&client_id=' . rawurlencode($client->clientId),
        ));
        $metadataClient = $server->authorizeHandler()->handle($request(
            'GET',
            'https://example.com/oauth/authorize?client_id=' . rawurlencode('https://client.example/meta.json'),
        ));

        $this->assertSame(400, $token->getStatusCode());
        $this->assertSame('invalid_grant', json_decode((string)$token->getBody(), true)['error'] ?? null);
        $this->assertSame(400, $authorize->getStatusCode());
        $this->assertSame(201, $register->getStatusCode());
        $this->assertSame(200, $revoke->getStatusCode());
        $this->assertLessThan(500, $metadataClient->getStatusCode());
        $warnings = array_filter($logger->records, fn(array $record): bool => $record[0] === LogLevel::WARNING);
        $this->assertNotEmpty($warnings);
        $errors = array_filter($logger->records, fn(array $record): bool => $record[0] === LogLevel::ERROR);
        $this->assertSame([], $errors);
    }
}
