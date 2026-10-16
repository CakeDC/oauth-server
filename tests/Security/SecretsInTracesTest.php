<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Security;

use CakeDC\OAuth\Server\AuthorizationServer;
use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Client\ClientAuthMethod;
use CakeDC\OAuth\Server\Config\ServerConfig;
use CakeDC\OAuth\Server\Grant\RedirectUrl;
use CakeDC\OAuth\Server\Http\HttpResponder;
use CakeDC\OAuth\Server\Storage\Pdo\PdoStorage;
use CakeDC\OAuth\Server\Test\Support\FakeDns;
use CakeDC\OAuth\Server\Test\Support\FakeTransport;
use CakeDC\OAuth\Server\Test\Support\FakeUserContext;
use CakeDC\OAuth\Server\Test\Support\FakeUsers;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\HookedPdo;
use CakeDC\OAuth\Server\Test\Support\RecordingLogger;
use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use CakeDC\OAuth\Server\Testing\ArrayCache;
use CakeDC\OAuth\Server\Testing\FrozenClock;
use CakeDC\OAuth\Server\View\ConnectionsView;
use CakeDC\OAuth\Server\View\ConsentView;
use CakeDC\OAuth\Server\View\Html\HtmlConnectionsRenderer;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use ReflectionMethod;
use RuntimeException;
use SensitiveParameter;
use Throwable;

/**
 * A failure in the middle of a request (the database is gone) is logged with its exception, and loggers
 * print its stack trace. With `zend.exception_ignore_args` off (the engine default without a php.ini, as in
 * the official Docker images) the trace shows the arguments of every frame, so every parameter that
 * carries a token, a code, a verifier or a secret is a `#[\SensitiveParameter]`.
 */
class SecretsInTracesTest extends TestCase
{
    private const SECRET = 'server-secret-0123456789-abcdefghij';
    private const CLIENT_SECRET = 'client-secret-0123456789-abcdefghij';
    private const INITIAL_ACCESS_TOKEN = 'initial-access-token-0123456789-abcdef';

    /**
     * @var array{string|false, string|false}
     */
    private array $ini;

    private HookedPdo $pdo;

    private RecordingLogger $logger;

    private FakeUserContext $userContext;

    private FakeUsers $users;

    private AuthorizationServer $server;

    private Psr17Factory $factory;

    protected function setUp(): void
    {
        $this->ini = [ini_get('zend.exception_ignore_args'), ini_get('zend.exception_string_param_max_len')];
        if (
            ini_set('zend.exception_ignore_args', '0') === false
            || ini_set('zend.exception_string_param_max_len', '1000000') === false
        ) {
            $this->markTestSkipped(
                'zend.exception_ignore_args and zend.exception_string_param_max_len cannot be changed at run time '
                . 'here, so traces cannot be made to show full arguments.',
            );
        }
        $this->pdo = new HookedPdo('sqlite::memory:');
        PdoStorage::createTables($this->pdo);
        $this->logger = new RecordingLogger();
        $this->userContext = new FakeUserContext();
        $this->users = new FakeUsers();
        $this->factory = new Psr17Factory();
        $this->server = $this->buildServer($this->factory);
    }

    private function buildServer(ResponseFactoryInterface $responses): AuthorizationServer
    {
        $clock = new FrozenClock();

        return new AuthorizationServer(
            Fixtures::config(['secret' => self::SECRET]),
            new PdoStorage($this->pdo),
            $this->users,
            $this->userContext,
            $responses,
            $this->factory,
            cache: new ArrayCache($clock),
            clock: $clock,
            logger: $this->logger,
            transport: new FakeTransport(),
            dns: new FakeDns(),
        );
    }

    protected function tearDown(): void
    {
        if ($this->ini[0] !== false) {
            ini_set('zend.exception_ignore_args', $this->ini[0]);
        }
        if ($this->ini[1] !== false) {
            ini_set('zend.exception_string_param_max_len', $this->ini[1]);
        }
    }

    public function testTheSettingsMakeTracesShowFullArguments(): void
    {
        $leak = static function (string $value): never {
            throw new RuntimeException('boom');
        };
        try {
            $leak(self::CLIENT_SECRET);
        } catch (RuntimeException $e) {
            $this->assertStringContainsString(self::CLIENT_SECRET, $e->getTraceAsString());
        }
    }

    public function testAFailedRefreshDoesNotPutTheRefreshTokenInTheTrace(): void
    {
        $client = $this->confidentialClient();
        $tokens = $this->tokens($client);
        $this->pdo->beforePrepare('UPDATE oauth_tokens SET used_at', static function (): void {
            throw new RuntimeException('SQLSTATE[HY000]: General error: 2006 MySQL server has gone away');
        });

        $response = $this->server->tokenHandler()->handle($this->form('https://example.com/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $tokens['refresh_token'],
            'client_id' => $client->clientId,
            'client_secret' => self::CLIENT_SECRET,
        ]));

        $this->assertSame(500, $response->getStatusCode());
        $this->assertTraceHides($this->loggedFailure(), [$tokens['refresh_token'], self::CLIENT_SECRET]);
    }

    public function testAFailedCodeExchangeDoesNotPutTheCodeVerifierOrSecretInTheTrace(): void
    {
        $client = $this->confidentialClient();
        $code = $this->code($client);
        $this->pdo->beforePrepare('UPDATE oauth_authorization_codes SET used_at', static function (): void {
            throw new RuntimeException('SQLSTATE[HY000]: General error: 2006 MySQL server has gone away');
        });

        $response = $this->exchange($client, $code);

        $this->assertSame(500, $response->getStatusCode());
        $this->assertTraceHides($this->loggedFailure(), [$code, ServerHarness::VERIFIER, self::CLIENT_SECRET]);
    }

    public function testAFailedClientLookupDoesNotPutTheClientSecretInTheTrace(): void
    {
        $client = $this->confidentialClient();
        $code = $this->code($client);
        $this->pdo->beforePrepare('SELECT * FROM oauth_clients WHERE client_id_hash', static function (): void {
            throw new RuntimeException('SQLSTATE[HY000]: General error: 2006 MySQL server has gone away');
        });

        $this->assertSame(500, $this->exchange($client, $code)->getStatusCode());
        $this->assertTraceHides($this->loggedFailure(), [$code, ServerHarness::VERIFIER, self::CLIENT_SECRET]);
    }

    public function testAFailedIntrospectionRevocationOrBearerCheckDoesNotPutTheTokenInTheTrace(): void
    {
        $client = $this->confidentialClient();
        $tokens = $this->tokens($client);
        $failing = static function (): void {
            throw new RuntimeException('SQLSTATE[HY000]: General error: 2006 MySQL server has gone away');
        };
        $resourceServer = Fixtures::confidentialClient('rs-secret', [
            'clientId' => 'resource-server',
            'allowIntrospection' => true,
        ]);
        $this->server->storage()->saveClient($resourceServer);
        $basic = ['Authorization' => 'Basic ' . base64_encode('resource-server:rs-secret')];

        $this->pdo->beforePrepare('SELECT * FROM oauth_clients WHERE id', $failing);
        $introspection = $this->server->introspectHandler()->handle(
            $this->form('https://example.com/oauth/introspect', ['token' => $tokens['access_token']], $basic),
        );
        $this->assertSame(500, $introspection->getStatusCode());
        $this->assertTraceHides($this->loggedFailure(), [$tokens['access_token'], 'rs-secret']);

        $this->logger->records = [];
        $this->pdo->beforePrepare('SELECT * FROM oauth_tokens WHERE token_hash', $failing);
        $revocation = $this->server->revokeHandler()->handle($this->form('https://example.com/oauth/revoke', [
            'token' => $tokens['refresh_token'],
            'client_id' => $client->clientId,
            'client_secret' => self::CLIENT_SECRET,
        ]));
        $this->assertSame(500, $revocation->getStatusCode());
        $this->assertTraceHides($this->loggedFailure(), [$tokens['refresh_token'], self::CLIENT_SECRET]);

        $this->pdo->beforePrepare('SELECT * FROM oauth_clients WHERE id', $failing);
        $next = new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return new Response(200);
            }
        };
        try {
            $this->server->bearerMiddleware(Fixtures::MCP)->process(
                $this->request('GET', Fixtures::MCP, ['Authorization' => 'Bearer ' . $tokens['access_token']]),
                $next,
            );
            $this->fail('The storage failure did not surface.');
        } catch (RuntimeException $e) {
            $this->assertTraceHides($e, [$tokens['access_token']]);
        }

        $this->pdo->beforePrepare('SELECT * FROM oauth_clients WHERE id', $failing);
        try {
            $this->server->mcpTokenValidator(Fixtures::MCP)->validate($tokens['access_token']);
            $this->fail('The storage failure did not surface.');
        } catch (RuntimeException $e) {
            $this->assertTraceHides($e, [$tokens['access_token']]);
        }
    }

    /**
     * The code is issued, then the redirect that carries it is built: a failure there (a response factory
     * that throws) happens with the code-carrying URL in the arguments of `HttpResponder::redirect()`.
     */
    public function testAFailedAuthorizationRedirectDoesNotPutTheCodeInTheTrace(): void
    {
        $responses = new class implements ResponseFactoryInterface {
            public ?int $failOn = null;

            private Psr17Factory $factory;

            public function __construct()
            {
                $this->factory = new Psr17Factory();
            }

            public function createResponse(int $code = 200, string $reasonPhrase = ''): ResponseInterface
            {
                if ($code === $this->failOn) {
                    $this->failOn = null;
                    throw new RuntimeException('The response could not be built.');
                }

                return $this->factory->createResponse($code, $reasonPhrase);
            }
        };
        $this->server = $this->buildServer($responses);
        $client = $this->confidentialClient();
        $this->userContext->owner = $this->users->users['42'];
        $page = $this->server->authorizeHandler()->handle($this->request('GET', (new ServerHarness())->authorizeUrl($client)));
        $fields = ServerHarness::formFields((string)$page->getBody()) + ['decision' => 'approve'];

        $responses->failOn = 303;
        $answer = $this->server->authorizeHandler()->handle($this->form('https://example.com/oauth/authorize', $fields));

        $this->assertSame(500, $answer->getStatusCode());
        $this->assertSame(1, (int)$this->pdo->query('SELECT COUNT(*) FROM oauth_authorization_codes')?->fetchColumn());
        $failure = $this->loggedFailure();
        $this->assertStringContainsString('HttpResponder->redirect(', $failure->getTraceAsString());
        $this->assertTraceHides($failure, ['oauth_ac_', $fields['consent_token']]);
    }

    /**
     * Parameters that carry a code, a token or a form token but whose frames no test can catch on the stack
     * of a failure (a URL builder or a renderer helper that cannot fail today) are pinned here: removing the
     * attribute fails this test.
     *
     * @return array<string, array{class-string, string, string}>
     */
    public static function sensitiveParameters(): array
    {
        return [
            'RedirectUrl::build() $params' => [RedirectUrl::class, 'build', 'params'],
            'HttpResponder::redirect() $url' => [HttpResponder::class, 'redirect', 'url'],
            'HttpResponder::page() $html' => [HttpResponder::class, 'page', 'html'],
            'HttpResponder::json() $data' => [HttpResponder::class, 'json', 'data'],
            'ConsentView $fields (consent_token)' => [ConsentView::class, '__construct', 'fields'],
            'ConnectionsView $formToken' => [ConnectionsView::class, '__construct', 'formToken'],
            'ConnectionsView $newToken' => [ConnectionsView::class, '__construct', 'newToken'],
            'HtmlConnectionsRenderer::hidden() $value (form_token)' => [HtmlConnectionsRenderer::class, 'hidden', 'value'],
        ];
    }

    /**
     * @param class-string $class
     */
    #[DataProvider('sensitiveParameters')]
    public function testTheParameterIsSensitive(string $class, string $method, string $parameter): void
    {
        foreach ((new ReflectionMethod($class, $method))->getParameters() as $candidate) {
            if ($candidate->getName() === $parameter) {
                $this->assertNotSame([], $candidate->getAttributes(SensitiveParameter::class));

                return;
            }
        }
        $this->fail(sprintf('%s::%s() has no parameter $%s.', $class, $method, $parameter));
    }

    public function testAConfigurationErrorDoesNotPutTheSecretsInTheTrace(): void
    {
        try {
            ServerConfig::fromArray([
                'issuer' => 'https://example.com',
                'secret' => self::SECRET,
                'resources' => Fixtures::resourceSettings(),
                'registration' => ['mode' => 'token', 'initialAccessToken' => self::INITIAL_ACCESS_TOKEN],
                'routePrefix' => 'no-leading-slash',
            ]);
            $this->fail('The invalid route prefix was accepted.');
        } catch (Throwable $e) {
            $this->assertTraceHides($e, [self::SECRET, self::INITIAL_ACCESS_TOKEN]);
        }
    }

    /**
     * @param list<string> $secrets
     */
    private function assertTraceHides(Throwable $error, array $secrets): void
    {
        $rendered = '';
        for ($e = $error; $e !== null; $e = $e->getPrevious()) {
            $rendered .= $e->getTraceAsString() . "\n" . $e;
        }
        $this->assertStringContainsString('#1 ', $rendered, 'The trace is empty.');
        // Tools such as Symfony's error handler or Sentry also read the raw arguments, arrays included.
        $arguments = [];
        for ($e = $error; $e !== null; $e = $e->getPrevious()) {
            foreach ($e->getTrace() as $frame) {
                $args = $frame['args'] ?? [];
                array_walk_recursive($args, function (mixed $value) use (&$arguments): void {
                    if (is_string($value)) {
                        $arguments[] = $value;
                    }
                });
            }
        }
        foreach ($secrets as $secret) {
            $this->assertStringNotContainsString($secret, $rendered);
            $this->assertStringNotContainsString(substr($secret, 0, 15), $rendered);
            foreach ($arguments as $argument) {
                $this->assertStringNotContainsString($secret, $argument);
            }
        }
    }

    private function loggedFailure(): Throwable
    {
        foreach ($this->logger->records as [, , $context]) {
            if (($context['exception'] ?? null) instanceof Throwable) {
                return $context['exception'];
            }
        }
        $this->fail('No exception was logged.');
    }

    private function confidentialClient(): Client
    {
        $client = Fixtures::confidentialClient(self::CLIENT_SECRET, ['authMethod' => ClientAuthMethod::SecretPost]);
        $this->server->storage()->saveClient($client);

        return $client;
    }

    private function code(Client $client): string
    {
        $this->userContext->owner = $this->users->users['42'];
        $harness = new ServerHarness();
        $url = $harness->authorizeUrl($client);
        $page = $this->server->authorizeHandler()->handle($this->request('GET', $url));
        $fields = ServerHarness::formFields((string)$page->getBody()) + ['decision' => 'approve'];
        $answer = $this->server->authorizeHandler()->handle($this->form('https://example.com/oauth/authorize', $fields));
        $code = ServerHarness::redirectParams($answer)['code'] ?? null;
        $this->assertIsString($code, 'No code: ' . $answer->getHeaderLine('Location'));

        return $code;
    }

    /**
     * @return array<string, mixed>
     */
    private function tokens(Client $client): array
    {
        $tokens = json_decode((string)$this->exchange($client, $this->code($client))->getBody(), true);
        $this->assertIsArray($tokens);
        $this->assertArrayHasKey('refresh_token', $tokens);

        return $tokens;
    }

    private function exchange(Client $client, #[SensitiveParameter] string $code): ResponseInterface
    {
        return $this->server->tokenHandler()->handle($this->form('https://example.com/oauth/token', [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $client->redirectUris[0],
            'code_verifier' => ServerHarness::VERIFIER,
            'client_id' => $client->clientId,
            'client_secret' => self::CLIENT_SECRET,
        ]));
    }

    /**
     * @param array<string, string> $headers
     */
    private function request(string $method, string $uri, array $headers = [], string $body = ''): ServerRequest
    {
        return new ServerRequest($method, $uri, $headers, $body, '1.1', ['REMOTE_ADDR' => ServerHarness::IP]);
    }

    /**
     * @param array<string, string> $fields
     * @param array<string, string> $headers
     */
    private function form(string $uri, array $fields, array $headers = []): ServerRequest
    {
        return $this->request(
            'POST',
            $uri,
            $headers + ['Content-Type' => 'application/x-www-form-urlencoded'],
            http_build_query($fields, '', '&', PHP_QUERY_RFC3986),
        );
    }
}
