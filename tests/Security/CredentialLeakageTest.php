<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Security;

use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use RuntimeException;

/**
 * RFC 9700, "Credential Leakage via Referer Headers" and "via Browser History", and "Access Token
 * Leakage": pages send no Referer and are not cached, tokens never travel in URLs or logs.
 */
class CredentialLeakageTest extends TestCase
{
    public function testPagesAndTokenResponsesAreNotStored(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $harness->signIn();
        $page = $harness->server->authorizeHandler()->handle($harness->request('GET', $harness->authorizeUrl($client)));

        $this->assertSame('no-referrer', $page->getHeaderLine('Referrer-Policy'));
        $this->assertSame('no-store', $page->getHeaderLine('Cache-Control'));
        $token = $harness->exchange($client, $harness->authorizationCode($client));
        $this->assertSame('no-store', $token->getHeaderLine('Cache-Control'));
    }

    public function testOnlyTheCodeTravelsInTheRedirect(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $harness->authorizationCode($client);

        $response = $harness->server->authorizeHandler()->handle($harness->request('GET', $harness->authorizeUrl($client)));

        $this->assertSame(['code', 'state', 'iss'], array_keys(ServerHarness::redirectParams($response)));
    }

    public function testTokensInTheQueryStringAreIgnored(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $token = $harness->json($harness->exchange($client, $harness->authorizationCode($client)))['access_token'];
        $next = new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return new Response(200);
            }
        };

        $response = $harness->server->bearerMiddleware(Fixtures::MCP)->process(
            $harness->request('GET', Fixtures::MCP . '?access_token=' . $token),
            $next,
        );

        $this->assertSame(401, $response->getStatusCode());
    }

    public function testLogsNeverContainSecrets(): void
    {
        $harness = new ServerHarness();
        $client = $harness->confidentialClient('the-client-secret');
        $basic = ['Authorization' => 'Basic ' . base64_encode($client->clientId . ':the-client-secret')];
        $code = $harness->authorizationCode($client);
        $tokens = $harness->json($harness->exchange($client, $code, [], $basic));
        $harness->exchange($client, $code, [], $basic);
        $harness->server->tokenHandler()->handle($harness->form('https://example.com/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $tokens['refresh_token'] . 'x',
        ], $basic));
        $this->assertSame([], $harness->logger->records, 'Expected failures are not logged');

        // A real failure while the secrets are in flight: the server logs it, without any secret.
        $fresh = $harness->authorizationCode($client);
        $harness->events->hook = function (object $event): void {
            throw new RuntimeException('database went away');
        };
        $response = $harness->exchange($client, $fresh, [], $basic);
        $this->assertSame(500, $response->getStatusCode());

        $log = $harness->logger->text();
        $this->assertNotSame([], $harness->logger->records);
        $this->assertStringContainsString('RuntimeException: database went away', $log);
        $secrets = [
            $code,
            $fresh,
            ServerHarness::VERIFIER,
            'the-client-secret',
            $tokens['access_token'],
            $tokens['refresh_token'],
        ];
        foreach ($secrets as $secret) {
            $this->assertStringNotContainsString($secret, $log);
        }
    }
}
