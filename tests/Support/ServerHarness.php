<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Support;

use CakeDC\OAuth\Server\AuthorizationServer;
use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Grant\Pkce;
use CakeDC\OAuth\Server\Storage\InMemory\InMemoryStorage;
use CakeDC\OAuth\Server\Testing\ArrayCache;
use CakeDC\OAuth\Server\Testing\FrozenClock;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use RuntimeException;

/**
 * A whole server on in-memory storage and fakes, for endpoint and end-to-end tests.
 */
final class ServerHarness
{
    public const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    public const IP = '203.0.113.7';

    public InMemoryStorage $storage;

    public FrozenClock $clock;

    public FakeUsers $users;

    public FakeUserContext $userContext;

    public RecordingEventDispatcher $events;

    public RecordingLogger $logger;

    public FakeDns $dns;

    public FakeTransport $transport;

    public ArrayCache $cache;

    public Psr17Factory $factory;

    public AuthorizationServer $server;

    /**
     * @param array<string, mixed> $config Overrides of Fixtures::config().
     */
    public function __construct(array $config = [])
    {
        $this->storage = new InMemoryStorage();
        $this->clock = new FrozenClock();
        $this->users = new FakeUsers();
        $this->userContext = new FakeUserContext();
        $this->events = new RecordingEventDispatcher();
        $this->logger = new RecordingLogger();
        $this->dns = new FakeDns();
        $this->transport = new FakeTransport();
        $this->cache = new ArrayCache($this->clock);
        $this->factory = new Psr17Factory();
        $this->server = new AuthorizationServer(
            Fixtures::config($config),
            $this->storage,
            $this->users,
            $this->userContext,
            $this->factory,
            $this->factory,
            events: $this->events,
            cache: $this->cache,
            clock: $this->clock,
            logger: $this->logger,
            transport: $this->transport,
            dns: $this->dns,
        );
    }

    /**
     * @param array<string, string> $headers
     */
    public function request(string $method, string $uri, array $headers = [], string $body = ''): ServerRequestInterface
    {
        return new ServerRequest($method, $uri, $headers, $body, '1.1', ['REMOTE_ADDR' => self::IP]);
    }

    /**
     * @param array<string, string> $fields
     * @param array<string, string> $headers
     */
    public function form(string $uri, array $fields, array $headers = []): ServerRequestInterface
    {
        return $this->request(
            'POST',
            $uri,
            $headers + ['Content-Type' => 'application/x-www-form-urlencoded'],
            http_build_query($fields, '', '&', PHP_QUERY_RFC3986),
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function json(ResponseInterface $response): array
    {
        $data = json_decode((string)$response->getBody(), true);

        return is_array($data) ? $data : [];
    }

    /**
     * @param array<string, mixed> $overrides
     */
    public function publicClient(array $overrides = []): Client
    {
        $client = Fixtures::client($overrides);
        $this->storage->saveClient($client);

        return $client;
    }

    /**
     * @param array<string, mixed> $overrides
     */
    public function confidentialClient(string $secret = 'cs-secret', array $overrides = []): Client
    {
        $client = Fixtures::confidentialClient($secret, $overrides);
        $this->storage->saveClient($client);

        return $client;
    }

    public function signIn(string $subject = '42'): void
    {
        $this->userContext->owner = $this->users->users[$subject];
    }

    /**
     * The authorization URL for $client, PKCE included.
     *
     * @param array<string, string|null> $params Overrides; null removes a parameter.
     */
    public function authorizeUrl(Client $client, array $params = []): string
    {
        $query = array_filter($params + [
            'response_type' => 'code',
            'client_id' => $client->clientId,
            'redirect_uri' => $client->redirectUris[0],
            'state' => 'st4te',
            'code_challenge' => Pkce::challengeFor(self::VERIFIER),
            'code_challenge_method' => 'S256',
            'scope' => 'content:write',
            'resource' => Fixtures::MCP,
        ], fn(?string $value): bool => $value !== null);

        return 'https://example.com/oauth/authorize?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * The hidden fields of the consent form in $html.
     *
     * @return array<string, string>
     */
    public static function formFields(string $html): array
    {
        preg_match_all('/<input type="hidden" name="([^"]+)" value="([^"]*)"/', $html, $matches, PREG_SET_ORDER);
        $fields = [];
        foreach ($matches as $match) {
            $fields[html_entity_decode($match[1])] = html_entity_decode($match[2], ENT_QUOTES);
        }

        return $fields;
    }

    /**
     * The query parameters of a redirect response.
     *
     * @return array<string, string>
     */
    public static function redirectParams(ResponseInterface $response): array
    {
        parse_str((string)parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $params);

        /** @var array<string, string> $params */
        return $params;
    }

    /**
     * Signs in, approves the consent page and returns the authorization code.
     *
     * @param array<string, string|null> $params Authorization parameter overrides.
     */
    public function authorizationCode(Client $client, array $params = [], string $subject = '42'): string
    {
        $this->signIn($subject);
        $page = $this->server->authorizeHandler()->handle(
            $this->request('GET', $this->authorizeUrl($client, $params)),
        );
        if ($page->getStatusCode() === 302) {
            return self::redirectParams($page)['code'] ?? throw new RuntimeException('No code in the redirect.');
        }
        $fields = self::formFields((string)$page->getBody()) + ['decision' => 'approve'];
        $response = $this->server->authorizeHandler()->handle(
            $this->form('https://example.com/oauth/authorize', $fields),
        );

        return self::redirectParams($response)['code']
            ?? throw new RuntimeException('No code: ' . $response->getHeaderLine('Location'));
    }

    /**
     * Exchanges a code at the token endpoint.
     *
     * @param array<string, string> $extra More form fields.
     * @param array<string, string> $headers Headers.
     */
    public function exchange(Client $client, string $code, array $extra = [], array $headers = []): ResponseInterface
    {
        return $this->server->tokenHandler()->handle($this->form('https://example.com/oauth/token', $extra + [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $client->redirectUris[0],
            'code_verifier' => self::VERIFIER,
            'client_id' => $client->clientId,
        ], $headers));
    }

    /**
     * The status the bearer middleware answers for $token at $resource.
     *
     * @param list<string> $scopes Scopes the route requires.
     */
    public function bearerStatus(string $resource, string $token, array $scopes = []): int
    {
        $next = new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return new Response(200);
            }
        };

        return $this->server->bearerMiddleware($resource, null, $scopes)
            ->process($this->request('GET', $resource, ['Authorization' => 'Bearer ' . $token]), $next)
            ->getStatusCode();
    }
}
