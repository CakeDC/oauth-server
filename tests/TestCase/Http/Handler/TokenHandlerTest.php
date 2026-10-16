<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Http\Handler;

use CakeDC\OAuth\Server\AuthorizationServer;
use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Event\TokenIssued;
use CakeDC\OAuth\Server\Http\Handler\TokenHandler;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Test\Support\FakeUsers;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\FlakyClientRepository;
use CakeDC\OAuth\Server\Test\Support\RacingCodes;
use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use CakeDC\OAuth\Server\Token\TokenType;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use ReflectionClass;
use ReflectionProperty;
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

    public function testACodeNeverGrantsMoreThanThePersonMayHoldAtExchange(): void
    {
        $client = $this->harness->publicClient();
        $code = $this->harness->authorizationCode($client, ['scope' => 'content:read content:write']);
        $this->harness->users->scopes['42'] = ['content:read'];

        $body = $this->harness->json($this->harness->exchange($client, $code));

        $this->assertSame('content:read', $body['scope']);
    }

    public function testACodeWithNoScopeLeftIsRefusedAndNotConsumed(): void
    {
        $client = $this->harness->publicClient();
        $code = $this->harness->authorizationCode($client);
        $this->harness->users->scopes['42'] = [];

        $this->assertError($this->harness->exchange($client, $code), 'invalid_grant');
        $this->assertNull($this->harness->storage->findCodeByHash(TokenGenerator::hash($code))?->usedAt);
        $this->assertSame([], $this->harness->events->ofType(TokenIssued::class));

        $this->harness->users->scopes['42'] = null;
        $this->assertSame(200, $this->harness->exchange($client, $code)->getStatusCode());
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

    /**
     * @param array<string, string|null> $overrides Null removes a field.
     * @return array<string, string>
     */
    private function codeFields(Client $client, string $code, array $overrides = []): array
    {
        return array_filter($overrides + [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $client->redirectUris[0],
            'code_verifier' => ServerHarness::VERIFIER,
            'client_id' => $client->clientId,
        ], fn(?string $value): bool => $value !== null);
    }

    /**
     * A token handler whose code repository is wrapped in a RacingCodes.
     *
     * @return array{0: \CakeDC\OAuth\Server\Http\Handler\TokenHandler, 1: \CakeDC\OAuth\Server\Test\Support\RacingCodes}
     */
    private function racingHandler(): array
    {
        $real = $this->harness->server->tokenHandler();
        $racing = new RacingCodes($this->harness->storage);
        $args = [];
        foreach ((new ReflectionClass(TokenHandler::class))->getConstructor()?->getParameters() ?? [] as $parameter) {
            $args[$parameter->getName()] = (new ReflectionProperty($real, $parameter->getName()))->getValue($real);
        }
        $args['codes'] = $racing;

        return [new TokenHandler(...$args), $racing];
    }

    /**
     * @param \CakeDC\OAuth\Server\Test\Support\RacingCodes $racing The wrapper that saw the families.
     */
    private function assertEveryFamilyRevoked(RacingCodes $racing, string $code): void
    {
        $families = $racing->families;
        $stored = $this->harness->storage->findCodeByHash(TokenGenerator::hash($code));
        if ($stored?->familyId !== null) {
            $families[] = $stored->familyId;
        }
        $this->assertNotEmpty($families);
        foreach (array_unique($families) as $family) {
            $tokens = $this->harness->storage->findTokensByFamily($family);
            $this->assertNotEmpty($tokens);
            foreach ($tokens as $token) {
                $this->assertNotNull($token->revokedAt, 'A token of a raced code stayed live.');
            }
        }
    }

    public function testRaceWhereTheOtherRequestSeesAUsedCode(): void
    {
        $client = $this->harness->publicClient();
        $code = $this->harness->authorizationCode($client);
        [$handler, $racing] = $this->racingHandler();
        $request = fn() => $handler->handle($this->harness->form(
            'https://example.com/oauth/token',
            $this->codeFields($client, $code),
        ));
        $loser = null;
        $racing->afterConsume = function () use (&$loser, $request): void {
            $loser = $request();
        };

        $request();

        $this->assertNotNull($loser);
        $this->assertError($loser, 'invalid_grant');
        $this->assertEveryFamilyRevoked($racing, $code);
    }

    public function testRaceWhereTheOtherRequestConsumesFirst(): void
    {
        $client = $this->harness->publicClient();
        $code = $this->harness->authorizationCode($client);
        [$handler, $racing] = $this->racingHandler();
        $request = fn() => $handler->handle($this->harness->form(
            'https://example.com/oauth/token',
            $this->codeFields($client, $code),
        ));
        $inner = null;
        $racing->beforeConsume = function () use (&$inner, $request): void {
            $inner = $request();
        };

        $outer = $request();

        $this->assertSame(200, $inner?->getStatusCode());
        $this->assertError($outer, 'invalid_grant');
        $this->assertCount(2, $racing->families);
        $this->assertEveryFamilyRevoked($racing, $code);
    }

    public function testRedirectUriIsRequiredWithSeveralRegisteredUris(): void
    {
        $multi = $this->harness->publicClient(['redirectUris' => ['https://app.example.com/cb', 'https://app.example.com/cb2']]);
        $code = $this->harness->authorizationCode($multi);
        $this->assertError(
            $this->post($this->codeFields($multi, $code, ['redirect_uri' => null])),
            'invalid_request',
        );
        $this->assertSame(200, $this->post($this->codeFields($multi, $code))->getStatusCode());

        $single = $this->harness->publicClient();
        $code = $this->harness->authorizationCode($single);
        $this->assertSame(
            200,
            $this->post($this->codeFields($single, $code, ['redirect_uri' => null]))->getStatusCode(),
        );
    }

    public function testAUsedCodeNeedsTheRightVerifierToRevokeAnything(): void
    {
        $client = $this->harness->publicClient();
        $code = $this->harness->authorizationCode($client);
        $pair = $this->harness->json($this->harness->exchange($client, $code));
        $access = TokenGenerator::hash($pair['access_token']);

        $this->assertError(
            $this->harness->exchange($client, $code, ['code_verifier' => str_repeat('x', 43)]),
            'invalid_grant',
        );
        $this->assertNull($this->harness->storage->findTokenByHash($access)?->revokedAt);

        $this->assertError($this->harness->exchange($client, $code), 'invalid_grant');
        $this->assertNotNull($this->harness->storage->findTokenByHash($access)?->revokedAt);
    }

    public function testAnotherClientCannotBurnAVictimsCode(): void
    {
        $victim = $this->harness->publicClient();
        $attacker = $this->harness->publicClient();
        $code = $this->harness->authorizationCode($victim);

        $this->assertError($this->harness->exchange($attacker, $code), 'invalid_grant');
        $this->assertSame(200, $this->harness->exchange($victim, $code)->getStatusCode());
    }

    public function testAnotherClientReplayingAUsedCodeLeavesTheFamilyAlive(): void
    {
        $victim = $this->harness->publicClient();
        $attacker = $this->harness->publicClient();
        $code = $this->harness->authorizationCode($victim);
        $pair = $this->harness->json($this->harness->exchange($victim, $code));

        $this->assertError($this->harness->exchange($attacker, $code), 'invalid_grant');
        $stored = $this->harness->storage->findTokenByHash(TokenGenerator::hash($pair['access_token']));
        $this->assertNull($stored?->revokedAt);
    }

    public function testAWrongVerifierLeavesTheCodeUsable(): void
    {
        $client = $this->harness->publicClient();
        $code = $this->harness->authorizationCode($client);

        $this->assertError(
            $this->harness->exchange($client, $code, ['code_verifier' => str_repeat('x', 43)]),
            'invalid_grant',
        );
        $this->assertSame(200, $this->harness->exchange($client, $code)->getStatusCode());
    }

    public function testACodeWhoseResourceWasRemovedIsRejected(): void
    {
        $client = $this->harness->publicClient();
        $code = $this->harness->authorizationCode($client);
        $settings = Fixtures::resourceSettings();
        unset($settings[Fixtures::MCP]);
        $server = new AuthorizationServer(
            Fixtures::config(['resources' => $settings]),
            $this->harness->storage,
            $this->harness->users,
            $this->harness->userContext,
            $this->harness->factory,
            $this->harness->factory,
            clock: $this->harness->clock,
            logger: $this->harness->logger,
        );

        $response = $server->tokenHandler()->handle(
            $this->harness->form('https://example.com/oauth/token', $this->codeFields($client, $code)),
        );

        $this->assertError($response, 'invalid_grant');
    }

    public function testClientsWithoutTheGrantAreUnauthorized(): void
    {
        $noCode = $this->harness->publicClient(['grantTypes' => ['refresh_token']]);
        $this->assertError($this->harness->exchange($noCode, 'whatever'), 'unauthorized_client');

        $noRefresh = $this->harness->publicClient(['grantTypes' => ['authorization_code']]);
        $this->assertError($this->post([
            'grant_type' => 'refresh_token',
            'refresh_token' => 'x',
            'client_id' => $noRefresh->clientId,
        ]), 'unauthorized_client');

        $this->harness->users->clientIdentity = new ResourceOwner('plain', 'Plain', null, SubjectType::Client);
        $this->harness->confidentialClient('s3cret', ['clientId' => 'plain', 'grantTypes' => ['authorization_code']]);
        $basic = ['Authorization' => 'Basic ' . base64_encode('plain:s3cret')];
        $this->assertError($this->post(['grant_type' => 'client_credentials'], $basic), 'unauthorized_client');
    }

    public function testRefreshAndClientCredentialsTouchTheClient(): void
    {
        $client = $this->harness->publicClient();
        $pair = $this->harness->json($this->harness->exchange($client, $this->harness->authorizationCode($client)));
        $this->harness->clock->advance(10);
        $this->post([
            'grant_type' => 'refresh_token',
            'refresh_token' => $pair['refresh_token'],
            'client_id' => $client->clientId,
        ]);
        $this->assertEquals(
            $this->harness->clock->now(),
            $this->harness->storage->findClientById($client->id)?->lastUsedAt,
        );

        $confidential = $this->harness->confidentialClient('s3cret', ['clientId' => 'reports', 'scopes' => ['api']]);
        $this->harness->users->clientIdentity = new ResourceOwner('reports', 'Job', null, SubjectType::Client);
        $this->harness->clock->advance(10);
        $response = $this->post(
            ['grant_type' => 'client_credentials', 'resource' => Fixtures::API],
            ['Authorization' => 'Basic ' . base64_encode('reports:s3cret')],
        );
        $this->assertSame(200, $response->getStatusCode());
        $this->assertEquals(
            $this->harness->clock->now(),
            $this->harness->storage->findClientById($confidential->id)?->lastUsedAt,
        );
    }

    public function testErrorsCarryNoStoreCorsAndChallenges(): void
    {
        $error = $this->post(['grant_type' => 'password']);
        $this->assertSame('no-store', $error->getHeaderLine('Cache-Control'));
        $this->assertSame('*', $error->getHeaderLine('Access-Control-Allow-Origin'));

        $this->harness->confidentialClient('s3cret', ['clientId' => 'reports']);
        $failed = $this->post(
            ['grant_type' => 'authorization_code', 'code' => 'x'],
            ['Authorization' => 'Basic ' . base64_encode('reports:wrong')],
        );
        $this->assertError($failed, 'invalid_client', 401);
        $this->assertStringStartsWith('Basic', $failed->getHeaderLine('WWW-Authenticate'));
    }

    public function testRateLimitAndPreflightHeaders(): void
    {
        $harness = new ServerHarness(['rateLimit' => ['token' => [1, 60]]]);
        $handler = $harness->server->tokenHandler();
        $request = fn() => $handler->handle($harness->form('https://example.com/oauth/token', ['grant_type' => 'x']));
        $this->assertSame(400, $request()->getStatusCode());
        $limited = $request();
        $this->assertSame(429, $limited->getStatusCode());
        $this->assertNotSame('', $limited->getHeaderLine('Retry-After'));
        $this->assertSame('*', $limited->getHeaderLine('Access-Control-Allow-Origin'));

        $preflight = $this->harness->server->tokenHandler()
            ->handle($this->harness->request('OPTIONS', 'https://example.com/oauth/token'));
        $this->assertSame('*', $preflight->getHeaderLine('Access-Control-Allow-Origin'));
        $this->assertStringContainsString('POST', $preflight->getHeaderLine('Access-Control-Allow-Methods'));
    }

    public function testAFailedIssuanceRevokesWhatWasSavedAndKeepsTheCode(): void
    {
        $client = $this->harness->publicClient();
        $code = $this->harness->authorizationCode($client);
        $failed = false;
        $this->harness->events->hook = function (object $event) use (&$failed): void {
            if (!$failed && $event instanceof TokenIssued) {
                $failed = true;

                throw new RuntimeException('listener broke');
            }
        };

        $this->assertError($this->harness->exchange($client, $code), 'server_error', 500);

        $stored = $this->harness->storage->findCodeByHash(TokenGenerator::hash($code));
        $this->assertNull($stored?->usedAt);
        $issued = $this->harness->events->ofType(TokenIssued::class);
        $this->assertCount(1, $issued);
        $family = $issued[0]->token->familyId;
        $tokens = $this->harness->storage->findTokensByFamily($family);
        $this->assertNotEmpty($tokens);
        foreach ($tokens as $token) {
            $this->assertNotNull($token->revokedAt);
        }
        $this->assertSame(200, $this->harness->exchange($client, $code)->getStatusCode());
    }

    public function testAFailingClientTouchDoesNotFailTheGrant(): void
    {
        $client = $this->harness->publicClient();
        $code = $this->harness->authorizationCode($client);
        $real = $this->harness->server->tokenHandler();
        $clients = new FlakyClientRepository($this->harness->storage);
        $clients->failTouch = true;
        $args = [];
        foreach ((new ReflectionClass(TokenHandler::class))->getConstructor()?->getParameters() ?? [] as $parameter) {
            $args[$parameter->getName()] = (new ReflectionProperty($real, $parameter->getName()))->getValue($real);
        }
        $args['clients'] = $clients;
        $handler = new TokenHandler(...$args);

        $response = $handler->handle(
            $this->harness->form('https://example.com/oauth/token', $this->codeFields($client, $code)),
        );

        $this->assertSame(200, $response->getStatusCode(), (string)$response->getBody());
        $this->assertStringContainsString('touch exploded', $this->harness->logger->text());
    }
}
