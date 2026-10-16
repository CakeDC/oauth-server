<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Http\Handler;

use CakeDC\OAuth\Server\Event\ClientRegistered;
use CakeDC\OAuth\Server\Test\Support\ChunkedStream;
use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

class RegisterHandlerTest extends TestCase
{
    private function register(ServerHarness $harness, string $body, array $headers = []): ResponseInterface
    {
        return $harness->server->registerHandler()->handle($harness->request(
            'POST',
            'https://example.com/oauth/register',
            $headers + ['Content-Type' => 'application/json'],
            $body,
        ));
    }

    public function testRegistersLikeClaudeDoes(): void
    {
        $harness = new ServerHarness();
        $response = $this->register($harness, (string)json_encode([
            'client_name' => 'Claude',
            'redirect_uris' => ['https://claude.ai/api/mcp/auth_callback'],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
        ]));
        $body = $harness->json($response);

        $this->assertSame(201, $response->getStatusCode());
        $this->assertSame('*', $response->getHeaderLine('Access-Control-Allow-Origin'));
        $this->assertSame('Claude', $body['client_name']);
        $this->assertSame('none', $body['token_endpoint_auth_method']);
        $this->assertNotNull($harness->storage->findClientByClientId($body['client_id']));
        $this->assertCount(1, $harness->events->ofType(ClientRegistered::class));
    }

    public function testRejectsBadBodies(): void
    {
        $harness = new ServerHarness();

        $this->assertSame('invalid_client_metadata', $harness->json($this->register($harness, 'x=1', ['Content-Type' => 'text/plain']))['error']);
        $this->assertSame('invalid_client_metadata', $harness->json($this->register($harness, '[1]'))['error']);
        $this->assertSame('invalid_client_metadata', $harness->json($this->register($harness, '"text"'))['error']);
        $this->assertSame('invalid_redirect_uri', $harness->json($this->register($harness, '{}'))['error']);
        $large = (string)json_encode(['redirect_uris' => ['https://a.example/cb'], 'client_name' => str_repeat('n', 17000)]);
        $this->assertSame('invalid_client_metadata', $harness->json($this->register($harness, $large))['error']);
    }

    public function testClosedRegistration(): void
    {
        $harness = new ServerHarness(['registration' => ['mode' => 'closed']]);

        $response = $this->register($harness, '{"redirect_uris":["https://a.example/cb"]}');

        $this->assertSame(403, $response->getStatusCode());
        $this->assertSame('access_denied', $harness->json($response)['error']);
    }

    public function testRegistrationWithAnInitialAccessToken(): void
    {
        $harness = new ServerHarness(['registration' => ['mode' => 'token', 'initialAccessToken' => 'let-me-in']]);
        $body = '{"redirect_uris":["https://a.example/cb"],"token_endpoint_auth_method":"none"}';

        $denied = $this->register($harness, $body, ['Authorization' => 'Bearer wrong']);
        $this->assertSame(401, $denied->getStatusCode());
        $this->assertSame('Bearer error="invalid_token"', $denied->getHeaderLine('WWW-Authenticate'));
        $this->assertSame(401, $this->register($harness, $body)->getStatusCode());
        $this->assertSame(201, $this->register($harness, $body, ['Authorization' => 'Bearer let-me-in'])->getStatusCode());
    }

    public function testRateLimited(): void
    {
        $harness = new ServerHarness(['rateLimit' => ['register' => [1, 3600]]]);
        $body = '{"redirect_uris":["https://a.example/cb"],"token_endpoint_auth_method":"none"}';

        $this->assertSame(201, $this->register($harness, $body)->getStatusCode());
        $this->assertSame(429, $this->register($harness, $body)->getStatusCode());
    }

    public function testMethods(): void
    {
        $harness = new ServerHarness();

        $this->assertSame(204, $harness->server->registerHandler()->handle($harness->request('OPTIONS', '/'))->getStatusCode());
        $this->assertSame(405, $harness->server->registerHandler()->handle($harness->request('GET', '/'))->getStatusCode());
    }

    public function testTokenGuessesAreThrottled(): void
    {
        $harness = new ServerHarness([
            'registration' => ['mode' => 'token', 'initialAccessToken' => 'let-me-in'],
            'rateLimit' => ['register' => [3, 3600]],
        ]);

        $codes = [];
        for ($i = 0; $i < 5; $i++) {
            $codes[] = $this->register($harness, '{}', ['Authorization' => 'Bearer guess' . $i])->getStatusCode();
        }

        $this->assertSame([401, 401, 401, 429, 429], $codes);
    }

    public function testContentTypeMustBeExactlyJson(): void
    {
        $harness = new ServerHarness();
        $body = '{"redirect_uris":["https://a.example/cb"],"token_endpoint_auth_method":"none"}';

        $bad = $this->register($harness, $body, ['Content-Type' => 'application/jsonx']);
        $this->assertSame('invalid_client_metadata', $harness->json($bad)['error']);
        $ok = $this->register($harness, $body, ['Content-Type' => 'application/json; charset=utf-8']);
        $this->assertSame(201, $ok->getStatusCode());
    }

    public function testBodyCapIsExact(): void
    {
        $harness = new ServerHarness();
        $prefix = '{"redirect_uris":["https://a.example/cb"],"token_endpoint_auth_method":"none","x":"';
        $make = fn(int $length): string => $prefix . str_repeat('a', $length - strlen($prefix) - 2) . '"}';

        $over = $this->register($harness, $make(16385));
        $this->assertSame(400, $over->getStatusCode());
        $this->assertSame('invalid_client_metadata', $harness->json($over)['error']);
        $edge = $this->register($harness, $make(16384));
        $this->assertSame(201, $edge->getStatusCode());
    }

    public function testNoStoreAndAnyJsonObjectShape(): void
    {
        $harness = new ServerHarness();

        $response = $this->register($harness, '{"redirect_uris":["https://a.example/cb"],"token_endpoint_auth_method":"none"}');
        $this->assertSame('no-store', $response->getHeaderLine('Cache-Control'));

        $this->assertSame('invalid_client_metadata', $harness->json($this->register($harness, '[]'))['error']);
        $this->assertSame('invalid_redirect_uri', $harness->json($this->register($harness, '{"0":"x"}'))['error']);
    }

    public function testBadJsonIsRefused(): void
    {
        $harness = new ServerHarness();
        $deep = str_repeat('[', 100) . str_repeat(']', 100);

        $this->assertSame('invalid_client_metadata', $harness->json($this->register($harness, "{\"a\":\"\xB1\xB2\"}"))['error']);
        $this->assertSame('invalid_client_metadata', $harness->json($this->register($harness, '{"a":' . $deep . '}'))['error']);
    }

    public function testMissingAuthorizationHeaderGetsABareChallenge(): void
    {
        $harness = new ServerHarness(['registration' => ['mode' => 'token', 'initialAccessToken' => 'let-me-in']]);

        $response = $this->register($harness, '{}');

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame('Bearer', $response->getHeaderLine('WWW-Authenticate'));
    }

    public function testChunkedNonSeekableBodiesAreReadAndCapped(): void
    {
        $harness = new ServerHarness();
        $prefix = '{"redirect_uris":["https://a.example/cb"],"token_endpoint_auth_method":"none","x":"';
        $make = fn(int $length): string => $prefix . str_repeat('a', $length - strlen($prefix) - 2) . '"}';
        $send = fn(string $body) => $harness->server->registerHandler()->handle(
            $harness->request('POST', 'https://example.com/oauth/register', ['Content-Type' => 'application/json'])
                ->withBody(new ChunkedStream($body)),
        );

        $this->assertSame(201, $send($make(16384))->getStatusCode());
        $this->assertSame('invalid_client_metadata', $harness->json($send($make(40000)))['error']);
    }
}
