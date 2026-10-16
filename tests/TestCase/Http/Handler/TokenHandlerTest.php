<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Http\Handler;

use CakeDC\OAuth\Server\AuthorizationServer;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Test\Support\FakeUsers;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use CakeDC\OAuth\Server\Token\TokenType;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

class TokenHandlerTest extends TestCase
{
    private ServerHarness $harness;

    protected function setUp(): void
    {
        $this->harness = new ServerHarness();
    }

    private function assertError(ResponseInterface $response, string $error, int $status = 400): void
    {
        $this->assertSame($status, $response->getStatusCode(), (string)$response->getBody());
        $this->assertSame($error, $this->harness->json($response)['error'] ?? null);
    }

    /**
     * @param array<string, string> $fields
     * @param array<string, string> $headers
     */
    private function post(array $fields, array $headers = []): ResponseInterface
    {
        return $this->harness->server->tokenHandler()->handle($this->harness->form('https://example.com/oauth/token', $fields, $headers));
    }

    public function testExchangesACodeForAPair(): void
    {
        $client = $this->harness->publicClient();
        $code = $this->harness->authorizationCode($client);

        $response = $this->harness->exchange($client, $code);
        $body = $this->harness->json($response);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('application/json', $response->getHeaderLine('Content-Type'));
        $this->assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        $this->assertSame('*', $response->getHeaderLine('Access-Control-Allow-Origin'));
        $this->assertSame('Bearer', $body['token_type']);
        $this->assertSame(3600, $body['expires_in']);
        $this->assertSame('content:write', $body['scope']);
        $this->assertStringStartsWith('oauth_at_', $body['access_token']);
        $this->assertStringStartsWith('oauth_rt_', $body['refresh_token']);
        $this->assertNotNull($this->harness->storage->findClientById($client->id)?->lastUsedAt);
    }

    public function testACodeWorksOnceAndReuseRevokesWhatItIssued(): void
    {
        $client = $this->harness->publicClient();
        $code = $this->harness->authorizationCode($client);
        $first = $this->harness->json($this->harness->exchange($client, $code));

        $this->assertError($this->harness->exchange($client, $code), 'invalid_grant');

        $access = $this->harness->storage->findTokenByHash(TokenGenerator::hash($first['access_token']));
        $this->assertNotNull($access?->revokedAt);
    }

    public function testCodeChecks(): void
    {
        $client = $this->harness->publicClient();
        $other = $this->harness->publicClient();

        $this->assertError($this->harness->exchange($client, $this->harness->authorizationCode($client), ['code_verifier' => str_repeat('x', 43)]), 'invalid_grant');
        $this->assertError($this->harness->exchange($client, $this->harness->authorizationCode($client), ['redirect_uri' => 'https://app.example.com/other']), 'invalid_grant');
        $this->assertError($this->harness->exchange($client, $this->harness->authorizationCode($client), ['code_verifier' => '']), 'invalid_request');
        $this->assertError($this->harness->exchange($client, $this->harness->authorizationCode($client), ['resource' => Fixtures::API]), 'invalid_target');
        $this->assertError($this->harness->exchange($other, $this->harness->authorizationCode($client)), 'invalid_grant');
        $this->assertError($this->harness->exchange($client, 'nonsense'), 'invalid_grant');

        $code = $this->harness->authorizationCode($client);
        $this->harness->clock->advance(61);
        $this->assertError($this->harness->exchange($client, $code), 'invalid_grant');
    }

    public function testCodeOfAUserWhoIsGoneIsRejected(): void
    {
        $client = $this->harness->publicClient();
        $code = $this->harness->authorizationCode($client);
        $this->harness->users->remove('42');

        $this->assertError($this->harness->exchange($client, $code), 'invalid_grant');
    }

    public function testRefreshTokenPolicy(): void
    {
        $harness = new ServerHarness(['refreshTokens' => 'offline_access']);
        $client = $harness->publicClient();

        $without = $harness->json($harness->exchange($client, $harness->authorizationCode($client)));
        $this->assertArrayNotHasKey('refresh_token', $without);

        $with = $harness->json($harness->exchange($client, $harness->authorizationCode($client, ['scope' => 'content:read offline_access'])));
        $this->assertArrayHasKey('refresh_token', $with);
        $this->assertSame('content:read', $with['scope']);

        $noGrant = $harness->publicClient(['grantTypes' => ['authorization_code']]);
        $body = $harness->json($harness->exchange($noGrant, $harness->authorizationCode($noGrant, ['scope' => 'content:read offline_access'])));
        $this->assertArrayNotHasKey('refresh_token', $body);
    }

    public function testRefreshes(): void
    {
        $client = $this->harness->publicClient();
        $pair = $this->harness->json($this->harness->exchange($client, $this->harness->authorizationCode($client)));

        $response = $this->post(['grant_type' => 'refresh_token', 'refresh_token' => $pair['refresh_token'], 'client_id' => $client->clientId, 'scope' => 'content:read offline_access']);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('content:read', $this->harness->json($response)['scope']);
        $this->assertError($this->post(['grant_type' => 'refresh_token', 'client_id' => $client->clientId]), 'invalid_request');
    }

    public function testClientCredentials(): void
    {
        $this->harness->confidentialClient('s3cret', ['clientId' => 'reports', 'scopes' => ['api']]);
        $basic = ['Authorization' => 'Basic ' . base64_encode('reports:s3cret')];

        $this->assertError($this->post(['grant_type' => 'client_credentials', 'resource' => Fixtures::API], $basic), 'unauthorized_client');

        $this->harness->users->clientIdentity = new ResourceOwner('reports', 'Reporting job', null, SubjectType::Client);
        $response = $this->post(['grant_type' => 'client_credentials', 'resource' => Fixtures::API], $basic);
        $body = $this->harness->json($response);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('api', $body['scope']);
        $this->assertArrayNotHasKey('refresh_token', $body);
        $stored = $this->harness->storage->findTokenByHash(TokenGenerator::hash($body['access_token']));
        $this->assertSame(SubjectType::Client, $stored?->subjectType);
        $this->assertSame('reports', $stored?->subject);
        $this->assertSame(TokenType::Access, $stored?->type);

        $this->assertError($this->post(['grant_type' => 'client_credentials', 'scope' => 'content:read'], $basic), 'invalid_scope');
        $this->assertError($this->post(['grant_type' => 'client_credentials', 'resource' => 'https://nope.example'], $basic), 'invalid_target');

        $public = $this->harness->publicClient();
        $this->assertError($this->post(['grant_type' => 'client_credentials', 'client_id' => $public->clientId]), 'unauthorized_client');

        $disabled = new ServerHarness(['clientCredentials' => false]);
        $response = $disabled->server->tokenHandler()->handle($disabled->form('https://example.com/oauth/token', ['grant_type' => 'client_credentials']));
        $this->assertSame('unsupported_grant_type', $disabled->json($response)['error']);
    }

    public function testRequestShape(): void
    {
        $client = $this->harness->publicClient();

        $this->assertError($this->post(['client_id' => $client->clientId]), 'invalid_request');
        $this->assertError($this->post(['grant_type' => 'password', 'client_id' => $client->clientId]), 'unsupported_grant_type');
        $this->assertError($this->post(['grant_type' => 'authorization_code', 'client_id' => 'nobody', 'code' => 'x']), 'invalid_client', 401);

        $json = $this->harness->server->tokenHandler()->handle(
            $this->harness->request('POST', 'https://example.com/oauth/token', ['Content-Type' => 'application/json'], '{}'),
        );
        $this->assertError($json, 'invalid_request');

        $repeated = $this->harness->server->tokenHandler()->handle($this->harness->request(
            'POST',
            'https://example.com/oauth/token',
            ['Content-Type' => 'application/x-www-form-urlencoded'],
            'grant_type=refresh_token&grant_type=authorization_code',
        ));
        $this->assertError($repeated, 'invalid_request');

        $this->assertSame(405, $this->harness->server->tokenHandler()->handle($this->harness->request('GET', 'https://example.com/oauth/token'))->getStatusCode());
        $this->assertSame(204, $this->harness->server->tokenHandler()->handle($this->harness->request('OPTIONS', 'https://example.com/oauth/token'))->getStatusCode());
    }

    public function testUnexpectedErrorsRevealNothing(): void
    {
        $client = $this->harness->publicClient();
        $code = $this->harness->authorizationCode($client);
        $broken = new class extends FakeUsers {
            public function findBySubject(string $subject): ?ResourceOwner
            {
                throw new RuntimeException('database password is hunter2');
            }
        };
        $server = new AuthorizationServer(
            Fixtures::config(),
            $this->harness->storage,
            $broken,
            $this->harness->userContext,
            $this->harness->factory,
            $this->harness->factory,
            clock: $this->harness->clock,
            logger: $this->harness->logger,
            transport: $this->harness->transport,
        );

        $response = $server->tokenHandler()->handle($this->harness->form('https://example.com/oauth/token', [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'code_verifier' => ServerHarness::VERIFIER,
            'client_id' => $client->clientId,
        ]));

        $this->assertError($response, 'server_error', 500);
        $this->assertStringNotContainsString('hunter2', (string)$response->getBody());
        $this->assertStringContainsString('hunter2', $this->harness->logger->text());
    }
}
