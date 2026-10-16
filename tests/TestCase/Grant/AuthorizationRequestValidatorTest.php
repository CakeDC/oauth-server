<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Grant;

use CakeDC\OAuth\Server\Client\Cimd\FetchedResponse;
use CakeDC\OAuth\Server\Client\Cimd\MetadataDocumentFetcher;
use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Client\ClientResolver;
use CakeDC\OAuth\Server\Grant\AuthorizationError;
use CakeDC\OAuth\Server\Grant\AuthorizationRequest;
use CakeDC\OAuth\Server\Grant\AuthorizationRequestValidator;
use CakeDC\OAuth\Server\Grant\Pkce;
use CakeDC\OAuth\Server\Storage\InMemory\InMemoryStorage;
use CakeDC\OAuth\Server\Test\Support\FakeDns;
use CakeDC\OAuth\Server\Test\Support\FakeTransport;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Testing\FrozenClock;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class AuthorizationRequestValidatorTest extends TestCase
{
    private InMemoryStorage $storage;

    private Client $client;

    private AuthorizationRequestValidator $validator;

    protected function setUp(): void
    {
        $this->storage = new InMemoryStorage();
        $this->client = Fixtures::client(['clientId' => 'app', 'redirectUris' => ['https://app.example.com/cb', 'http://127.0.0.1/cb']]);
        $this->storage->saveClient($this->client);
        $this->validator = new AuthorizationRequestValidator(
            new ClientResolver($this->storage, new FrozenClock()),
            Fixtures::resources(),
        );
    }

    /**
     * @return array<string, string>
     */
    private function params(array $changes = []): array
    {
        $params = $changes + [
            'response_type' => 'code',
            'client_id' => 'app',
            'redirect_uri' => 'https://app.example.com/cb',
            'state' => 'xyz',
            'code_challenge' => Pkce::challengeFor(str_repeat('v', 43)),
            'code_challenge_method' => 'S256',
            'scope' => 'content:write offline_access',
            'resource' => 'https://example.com/mcp/',
        ];

        return array_filter($params, fn(?string $v): bool => $v !== null);
    }

    private function error(array $params, array $repeated = []): AuthorizationError
    {
        try {
            $this->validator->validate($params, $repeated);
            $this->fail('Accepted');
        } catch (AuthorizationError $e) {
            return $e;
        }
    }

    public function testAcceptsAValidRequest(): void
    {
        $request = $this->validator->validate($this->params());

        $this->assertSame($this->client->id, $request->client->id);
        $this->assertSame('https://app.example.com/cb', $request->redirectUri);
        $this->assertSame('xyz', $request->state);
        $this->assertSame(Fixtures::MCP, $request->resource->identifier);
        $this->assertSame(['content:write'], $request->scopes);
        $this->assertTrue($request->offlineAccess);
        $this->assertSame(64, strlen($request->fingerprint()));
        $this->assertSame($this->params(), $request->formFields());
    }

    public function testDefaultsForClientsThatSendNeitherResourceNorScope(): void
    {
        $request = $this->validator->validate($this->params(['resource' => null, 'scope' => null, 'state' => null]));

        $this->assertSame(Fixtures::MCP, $request->resource->identifier);
        $this->assertSame([], $request->scopes);
        $this->assertFalse($request->offlineAccess);
        $this->assertNull($request->state);
    }

    public function testLoopbackRedirectWithAnyPort(): void
    {
        $request = $this->validator->validate($this->params(['redirect_uri' => 'http://127.0.0.1:61234/cb']));

        $this->assertSame('http://127.0.0.1:61234/cb', $request->redirectUri);
    }

    public function testRedirectUriMayBeOmittedOnlyWithASingleRegisteredOne(): void
    {
        $single = Fixtures::client(['clientId' => 'single']);
        $this->storage->saveClient($single);

        $request = $this->validator->validate($this->params(['client_id' => 'single', 'redirect_uri' => null]));
        $this->assertSame('https://app.example.com/cb', $request->redirectUri);

        $this->assertFalse($this->error($this->params(['redirect_uri' => null]))->isRedirectable());
    }

    /**
     * @return array<string, array{array<string, string|null>, list<string>, string}>
     */
    public static function shownErrors(): array
    {
        return [
            'no client' => [['client_id' => null], [], 'invalid_request'],
            'unknown client' => [['client_id' => 'nobody'], [], 'invalid_client'],
            'unregistered redirect' => [['redirect_uri' => 'https://evil.example/cb'], [], 'invalid_request'],
            'repeated client_id' => [[], ['client_id'], 'invalid_request'],
            'repeated redirect_uri' => [[], ['redirect_uri'], 'invalid_request'],
        ];
    }

    #[DataProvider('shownErrors')]
    public function testErrorsBeforeTheRedirectUriIsTrustedAreShown(array $changes, array $repeated, string $error): void
    {
        $e = $this->error($this->params($changes), $repeated);

        $this->assertFalse($e->isRedirectable());
        $this->assertSame($error, $e->error->error);
    }

    public function testRevokedClientsAreShownAnError(): void
    {
        $this->storage->saveClient($this->client->withRevokedAt(new DateTimeImmutable()));

        $this->assertFalse($this->error($this->params())->isRedirectable());
    }

    /**
     * @return array<string, array{array<string, string|null>, list<string>, string}>
     */
    public static function redirectedErrors(): array
    {
        return [
            'repeated scope' => [[], ['scope'], 'invalid_request'],
            'no response type' => [['response_type' => null], [], 'invalid_request'],
            'token response type' => [['response_type' => 'token'], [], 'unsupported_response_type'],
            'no challenge' => [['code_challenge' => null], [], 'invalid_request'],
            'plain method' => [['code_challenge_method' => 'plain'], [], 'invalid_request'],
            'no method' => [['code_challenge_method' => null], [], 'invalid_request'],
            'bad challenge' => [['code_challenge' => 'short'], [], 'invalid_request'],
            'unknown resource' => [['resource' => 'https://other.example/mcp'], [], 'invalid_target'],
            'unknown scope' => [['scope' => 'content:read admin'], [], 'invalid_scope'],
            'scope of another resource' => [['scope' => 'api'], [], 'invalid_scope'],
            'malformed scope' => [['scope' => 'a"b'], [], 'invalid_scope'],
        ];
    }

    #[DataProvider('redirectedErrors')]
    public function testLaterErrorsRedirectWithTheState(array $changes, array $repeated, string $error): void
    {
        $e = $this->error($this->params($changes), $repeated);

        $this->assertTrue($e->isRedirectable());
        $this->assertSame('https://app.example.com/cb', $e->redirectUri);
        $this->assertSame('xyz', $e->state);
        $this->assertSame($error, $e->error->error);
    }

    public function testClientsWithoutTheCodeGrantAreRejected(): void
    {
        $this->storage->saveClient(Fixtures::client(['clientId' => 'machine', 'grantTypes' => ['client_credentials']]));

        $e = $this->error($this->params(['client_id' => 'machine']));
        $this->assertSame('unauthorized_client', $e->error->error);
    }

    public function testAResolverFailureIsNeverRedirected(): void
    {
        $url = 'https://client.example.org/metadata.json';
        $transport = new FakeTransport();
        $transport->responses[$url] = new FetchedResponse(404, [], 'Not found');
        $validator = new AuthorizationRequestValidator(
            new ClientResolver(
                $this->storage,
                new FrozenClock(),
                new MetadataDocumentFetcher(new FakeDns(), $transport),
            ),
            Fixtures::resources(),
        );

        try {
            $validator->validate($this->params(['client_id' => $url]));
            $this->fail('Accepted');
        } catch (AuthorizationError $e) {
            $this->assertFalse($e->isRedirectable());
            $this->assertNull($e->redirectUri);
            $this->assertNull($e->state);
            $this->assertSame('invalid_client', $e->error->error);
        }
    }

    /**
     * @return array<string, array{string, string|null}>
     */
    public static function boundFields(): array
    {
        return [
            'client' => ['client_id', 'other'],
            'redirect uri' => ['redirect_uri', 'http://127.0.0.1/cb'],
            'state' => ['state', 'abc'],
            'scopes' => ['scope', 'content:read offline_access'],
            'offline access' => ['scope', 'content:write'],
            'code challenge' => ['code_challenge', 'A' . str_repeat('b', 42)],
        ];
    }

    #[DataProvider('boundFields')]
    public function testFingerprintChangesWithEachBoundField(string $field, ?string $value): void
    {
        $this->storage->saveClient(Fixtures::client([
            'clientId' => 'other',
            'redirectUris' => ['https://app.example.com/cb', 'http://127.0.0.1/cb'],
        ]));
        $changes = [$field => $value];
        $original = $this->validator->validate($this->params());
        $changed = $this->validator->validate($this->params($changes));

        $this->assertNotSame($original->fingerprint(), $changed->fingerprint());
    }

    public function testFingerprintChangesWithTheResourceAlone(): void
    {
        $original = $this->validator->validate($this->params());
        $other = new AuthorizationRequest(
            $original->client,
            $original->redirectUri,
            $original->state,
            Fixtures::resources()->get(Fixtures::API) ?? $this->fail('Missing resource'),
            $original->scopes,
            $original->offlineAccess,
            $original->codeChallenge,
            $original->params,
        );

        $this->assertNotSame($original->fingerprint(), $other->fingerprint());
    }

    public function testFormFieldsRoundTripKeepTheFingerprint(): void
    {
        $original = $this->validator->validate($this->params());
        $again = $this->validator->validate($original->formFields());

        $this->assertSame($original->fingerprint(), $again->fingerprint());
    }
}
