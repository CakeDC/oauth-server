<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Http\Handler;

use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;

class ConnectionsHandlerTest extends TestCase
{
    private const URL = 'https://example.com/oauth/connections';

    private ServerHarness $harness;

    protected function setUp(): void
    {
        $this->harness = new ServerHarness();
    }

    private function page(): ResponseInterface
    {
        return $this->harness->server->connectionsHandler()->handle($this->harness->request('GET', self::URL));
    }

    /**
     * @param array<string, string> $fields
     */
    private function post(array $fields, ?string $formToken = null): ResponseInterface
    {
        $token = $formToken ?? $this->harness->server->formToken()->issue('connections', '42');

        return $this->harness->server->connectionsHandler()->handle($this->harness->form(self::URL, $fields + ['form_token' => $token]));
    }

    public function testAnonymousVisitorsGoToTheLogin(): void
    {
        $response = $this->page();

        $this->assertSame(302, $response->getStatusCode());
        $this->assertSame('/oauth/connections', $this->harness->userContext->returnTo);
    }

    public function testListsAndRevokesConnections(): void
    {
        $client = $this->harness->publicClient(['name' => 'Claude']);
        $pair = $this->harness->json($this->harness->exchange($client, $this->harness->authorizationCode($client)));

        $html = (string)$this->page()->getBody();
        $this->assertStringContainsString('Claude', $html);
        $familyId = ServerHarness::formFields($html)['family_id'];

        $response = $this->post(['action' => 'revoke_connection', 'family_id' => $familyId]);

        $this->assertSame(303, $response->getStatusCode());
        $this->assertSame('/oauth/connections', $response->getHeaderLine('Location'));
        $this->assertNotNull($this->harness->storage->findTokenByHash(TokenGenerator::hash($pair['access_token']))?->revokedAt);
        $this->assertStringContainsString('No application is connected.', (string)$this->page()->getBody());
    }

    public function testCreatesAPersonalTokenShownOnce(): void
    {
        $this->harness->signIn();

        $response = $this->post([
            'action' => 'create_token',
            'name' => 'Deploy',
            'resource' => Fixtures::MCP,
            'scope:content:read' => '1',
            'days' => '30',
        ]);
        $html = (string)$response->getBody();

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        $this->assertMatchesRegularExpression('/<code>(oauth_pat_[A-Za-z0-9_-]{43})<\/code>/', $html);
        $this->assertStringContainsString('Deploy', (string)$this->page()->getBody());
        $this->assertStringNotContainsString('oauth_pat_', (string)$this->page()->getBody());
    }

    public function testInvalidTokenRequestsShowTheError(): void
    {
        $this->harness->signIn();

        $response = $this->post(['action' => 'create_token', 'name' => 'Deploy', 'resource' => Fixtures::MCP, 'days' => '30']);

        $this->assertSame(422, $response->getStatusCode());
        $this->assertStringContainsString('Choose at least one permission.', (string)$response->getBody());
    }

    public function testRevokesPersonalTokens(): void
    {
        $this->harness->signIn();
        $this->post(['action' => 'create_token', 'name' => 'Deploy', 'resource' => Fixtures::MCP, 'scope:content:read' => '1', 'days' => '7']);
        $tokenId = ServerHarness::formFields((string)$this->page()->getBody())['token_id'];

        $this->assertSame(303, $this->post(['action' => 'revoke_token', 'token_id' => $tokenId])->getStatusCode());
        $this->assertStringContainsString('You have no personal access tokens.', (string)$this->page()->getBody());
    }

    public function testRejectsForgedForms(): void
    {
        $this->harness->signIn();

        $this->assertSame(400, $this->post(['action' => 'revoke_token', 'token_id' => 'x'], 'forged')->getStatusCode());
        $this->assertSame(400, $this->post(['action' => 'explode'])->getStatusCode());
    }

    public function testDisabledFeatures(): void
    {
        $noPage = new ServerHarness(['connections' => false]);
        $noPage->signIn();
        $this->assertSame(404, $noPage->server->connectionsHandler()->handle($noPage->request('GET', self::URL))->getStatusCode());

        $this->harness = new ServerHarness(['personalTokens' => false]);
        $this->harness->signIn();
        $this->assertStringNotContainsString('Personal access tokens', (string)$this->page()->getBody());
        $this->assertSame(400, $this->post(['action' => 'create_token', 'name' => 'x'])->getStatusCode());
    }

    public function testRefusesUnsafePaths(): void
    {
        $this->harness->signIn();

        $uri = $this->createStub(UriInterface::class);
        $uri->method('getPath')->willReturn('/\\evil.example/connections');
        $uri->method('getQuery')->willReturn('');
        $request = $this->harness->request('GET', self::URL)->withUri($uri);

        $response = $this->harness->server->connectionsHandler()->handle($request);

        $this->assertSame(400, $response->getStatusCode());
    }

    public function testEscapesTheLoginReturnPath(): void
    {
        $this->harness->server->connectionsHandler()
            ->handle($this->harness->request('GET', 'https://example.com//evil.test/x?a=1'));

        $this->assertSame('/evil.test/x?a=1', $this->harness->userContext->returnTo);
    }
}
