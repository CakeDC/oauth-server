<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Http\Handler;

use CakeDC\OAuth\Server\AuthorizationServer;
use CakeDC\OAuth\Server\Client\ClientType;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
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

    public function testPersonalTokensCanBeListedAndRevokedWhenTheFeatureIsOff(): void
    {
        $this->harness->signIn();
        $owner = $this->harness->users->users['42'];
        $created = $this->harness->server->connectionService()
            ->createPersonalToken($owner, 'Deploy key', Fixtures::MCP, ['content:read'], 7);
        $off = new AuthorizationServer(
            Fixtures::config(['personalTokens' => false]),
            $this->harness->storage,
            $this->harness->users,
            $this->harness->userContext,
            $this->harness->factory,
            $this->harness->factory,
            cache: $this->harness->cache,
            clock: $this->harness->clock,
        );
        $handler = $off->connectionsHandler();
        $formToken = $off->formToken()->issue('connections', '42');

        $html = (string)$handler->handle($this->harness->request('GET', self::URL))->getBody();
        $this->assertStringContainsString('Deploy key', $html);
        $this->assertStringNotContainsString('name="name"', $html);
        $this->assertSame(400, $handler->handle($this->harness->form(self::URL, [
            'form_token' => $formToken, 'action' => 'create_token', 'name' => 'x',
        ]))->getStatusCode());
        $this->assertSame(303, $handler->handle($this->harness->form(self::URL, [
            'form_token' => $formToken, 'action' => 'revoke_token', 'token_id' => $created['token']->id,
        ]))->getStatusCode());
        $this->assertNotNull($this->harness->storage->findTokenById($created['token']->id)?->revokedAt);
    }

    public function testAnotherPersonsConnectionsAndTokensStayActive(): void
    {
        $client = $this->harness->publicClient();
        $victim = $this->harness->json($this->harness->exchange(
            $client,
            $this->harness->authorizationCode($client, [], '43'),
        ));
        $victimToken = $this->harness->storage->findTokenByHash(TokenGenerator::hash($victim['access_token']));
        $this->assertNotNull($victimToken);
        $personal = $this->harness->server->connectionService()->createPersonalToken(
            $this->harness->users->users['43'],
            'Victim key',
            Fixtures::MCP,
            ['content:read'],
            7,
        );
        $this->harness->signIn('42');

        $response = $this->post(['action' => 'revoke_connection', 'family_id' => $victimToken->familyId]);
        $this->assertSame(303, $response->getStatusCode());
        $response = $this->post(['action' => 'revoke_token', 'token_id' => $personal['token']->id]);
        $this->assertSame(303, $response->getStatusCode());

        $this->assertNull($this->harness->storage->findTokenById($victimToken->id)?->revokedAt);
        $this->assertNull($this->harness->storage->findTokenById($personal['token']->id)?->revokedAt);
        $this->assertNotNull($this->harness->storage->findConsent('43', $client->id, Fixtures::MCP));
    }

    public function testAScopeTheOwnerCannotGrantIsRefusedWith422(): void
    {
        $this->harness->signIn();

        $response = $this->post([
            'action' => 'create_token',
            'name' => 'Deploy',
            'resource' => Fixtures::MCP,
            'scope:content:read' => '1',
            'scope:evil' => '1',
            'days' => '7',
        ]);

        $this->assertSame(422, $response->getStatusCode());
        $this->assertStringContainsString('You cannot grant', (string)$response->getBody());
        $this->assertStringNotContainsString('oauth_pat_', (string)$response->getBody());
        $this->assertSame([], $this->harness->server->connectionService()->personalTokens($this->harness->users->users['42']));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function badDays(): array
    {
        return [
            'not a number' => ['abc'],
            'empty' => [''],
            'zero' => ['0'],
            'negative' => [' -5'],
            'minus' => ['-1'],
            'huge' => ['99999999999999999999999'],
            'exponent' => ['1e9'],
            'above the maximum' => ['91'],
        ];
    }

    #[DataProvider('badDays')]
    public function testHostileDayCountsAreRefusedWith422(string $days): void
    {
        $this->harness->signIn();

        $response = $this->post([
            'action' => 'create_token',
            'name' => 'Deploy',
            'resource' => Fixtures::MCP,
            'scope:content:read' => '1',
            'days' => $days,
        ]);

        $this->assertSame(422, $response->getStatusCode());
        $this->assertSame([], $this->harness->server->connectionService()->personalTokens($this->harness->users->users['42']));
    }

    public function testHostileTextIsEscapedEverywhere(): void
    {
        $evil = '<script>alert(1)</script>';
        $resources = Fixtures::resourceSettings();
        $resources[Fixtures::MCP]['scopes'][$evil] = '<img src=x onerror=alert(1)>';
        $this->harness = new ServerHarness(['resources' => $resources]);
        $client = $this->harness->publicClient([
            'name' => '<b onmouseover=alert(1)>Evil</b>',
            'type' => ClientType::MetadataDocument,
            'clientId' => 'https://evil<script>alert(1)</script>.example/client.json',
            'redirectUris' => ['https://evil.example/cb'],
        ]);
        $this->harness->server->tokenIssuer()->issue(
            $client,
            '42',
            SubjectType::User,
            $this->harness->server->config()->resources->get(Fixtures::MCP) ?? throw new LogicException('resource'),
            [$evil],
            'family-evil',
            true,
        );
        $this->harness->signIn();
        $this->post([
            'action' => 'create_token',
            'name' => '<script>name</script>',
            'resource' => Fixtures::MCP,
            'scope:' . $evil => '1',
            'days' => '7',
        ]);

        $page = (string)$this->page()->getBody();
        $refused = $this->post([
            'action' => 'create_token',
            'name' => 'x',
            'resource' => Fixtures::MCP,
            'scope:<img src=x>' => '1',
            'days' => '7',
        ]);

        foreach ([$page, (string)$refused->getBody()] as $html) {
            $this->assertStringNotContainsString('<script>', $html);
            $this->assertStringNotContainsString('<img src=x', $html);
            $this->assertStringNotContainsString('<b onmouseover', $html);
        }
        $this->assertStringContainsString('&lt;script&gt;', $page);
        $this->assertSame(422, $refused->getStatusCode());
        $this->assertStringContainsString('&lt;img src=x&gt;', (string)$refused->getBody());
    }

    public function testTheTokenValueNeverAppearsInALocationHeader(): void
    {
        $this->harness->signIn();

        $created = $this->post([
            'action' => 'create_token',
            'name' => 'Deploy',
            'resource' => Fixtures::MCP,
            'scope:content:read' => '1',
            'days' => '7',
        ]);
        preg_match('/<code>(oauth_pat_[A-Za-z0-9_-]+)<\/code>/', (string)$created->getBody(), $match);
        $this->assertNotEmpty($match);
        $tokenId = ServerHarness::formFields((string)$this->page()->getBody())['token_id'];
        $revoked = $this->post(['action' => 'revoke_token', 'token_id' => $tokenId]);

        $this->assertSame('', $created->getHeaderLine('Location'));
        $this->assertStringNotContainsString($match[1], $revoked->getHeaderLine('Location'));
        $this->assertStringNotContainsString('oauth_pat_', $revoked->getHeaderLine('Location'));
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
