<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\EndToEnd;

use CakeDC\OAuth\Server\Grant\Pkce;
use CakeDC\OAuth\Server\Test\Support\EchoApi;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use PHPUnit\Framework\TestCase;

/**
 * What claude.ai does with a custom connector, step by step, with Claude's real metadata document.
 */
class ClaudeConnectorFlowTest extends TestCase
{
    private const CLIENT_ID = 'https://claude.ai/oauth/mcp-oauth-client-metadata';
    private const CALLBACK = 'https://claude.ai/api/mcp/auth_callback';

    public function testTheWholeConnectorLife(): void
    {
        $harness = new ServerHarness();
        $harness->transport->serve(self::CLIENT_ID, [
            'client_id' => self::CLIENT_ID,
            'client_name' => 'Claude',
            'client_uri' => 'https://claude.ai',
            'redirect_uris' => [self::CALLBACK],
            'grant_types' => ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:jwt-bearer'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
        ]);
        $server = $harness->server;
        $api = new EchoApi();
        $protected = fn(string $token) => $server->bearerMiddleware(Fixtures::MCP)->process(
            $harness->request('POST', Fixtures::MCP, ['Authorization' => 'Bearer ' . $token]),
            $api,
        );

        // 1. Discovery: Claude reads the authorization server metadata.
        $metadata = $harness->json($server->metadataHandler()->handle(
            $harness->request('GET', 'https://example.com/.well-known/oauth-authorization-server'),
        ));
        $this->assertTrue($metadata['client_id_metadata_document_supported']);
        $this->assertContains('none', $metadata['token_endpoint_auth_methods_supported']);

        // 2. Authorization with Claude's CIMD client id; the person is not signed in yet.
        $query = http_build_query([
            'response_type' => 'code',
            'client_id' => self::CLIENT_ID,
            'redirect_uri' => self::CALLBACK,
            'scope' => 'content:write offline_access',
            'state' => 'claude-state',
            'code_challenge' => Pkce::challengeFor(ServerHarness::VERIFIER),
            'code_challenge_method' => 'S256',
            'resource' => Fixtures::MCP,
        ], '', '&', PHP_QUERY_RFC3986);
        $authorizeUrl = 'https://example.com/oauth/authorize?' . $query;
        $login = $server->authorizeHandler()->handle($harness->request('GET', $authorizeUrl));
        $this->assertSame(302, $login->getStatusCode());
        $this->assertStringStartsWith('/oauth/authorize?', (string)$harness->userContext->returnTo);

        // 3. After the login the consent page names claude.ai.
        $harness->signIn();
        $page = $server->authorizeHandler()->handle($harness->request('GET', $authorizeUrl));
        $html = (string)$page->getBody();
        $this->assertStringContainsString('claude.ai wants to access Example MCP', $html);
        $this->assertStringContainsString('claude.ai', $html);
        $this->assertStringNotContainsString('not verified', $html);

        // 4. Approve.
        $decision = $server->authorizeHandler()->handle($harness->form(
            'https://example.com/oauth/authorize',
            ServerHarness::formFields($html) + ['decision' => 'approve'],
        ));
        $params = ServerHarness::redirectParams($decision);
        $this->assertStringStartsWith(self::CALLBACK . '?', $decision->getHeaderLine('Location'));
        $this->assertSame('claude-state', $params['state']);
        $this->assertSame('https://example.com', $params['iss']);

        // 5. Token request with resource and PKCE, as a public client.
        $tokens = $harness->json($server->tokenHandler()->handle($harness->form('https://example.com/oauth/token', [
            'grant_type' => 'authorization_code',
            'code' => $params['code'],
            'redirect_uri' => self::CALLBACK,
            'code_verifier' => ServerHarness::VERIFIER,
            'client_id' => self::CLIENT_ID,
            'resource' => Fixtures::MCP,
        ])));
        $this->assertArrayHasKey('refresh_token', $tokens);
        $this->assertSame('content:write', $tokens['scope']);

        // 6. The MCP endpoint accepts the token and sees the person and the granted scopes.
        $this->assertSame(200, $protected($tokens['access_token'])->getStatusCode());
        $this->assertSame('42', $api->owner?->subject);
        $this->assertContains('content:write', (array)$api->scopes);
        $this->assertContains('content:read', (array)$api->scopes);
        $this->assertNotContains('content:publish', (array)$api->scopes);

        // 7. An hour later Claude refreshes, sending the resource again.
        $harness->clock->advance(3600);
        $this->assertSame(401, $protected($tokens['access_token'])->getStatusCode());
        $refreshed = $harness->json($server->tokenHandler()->handle($harness->form('https://example.com/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $tokens['refresh_token'],
            'client_id' => self::CLIENT_ID,
            'resource' => Fixtures::MCP,
        ])));
        $this->assertSame(200, $protected($refreshed['access_token'])->getStatusCode());
        $this->assertNotSame($tokens['refresh_token'], $refreshed['refresh_token']);

        // 8. The person revokes the connection on the connections page; Claude is out.
        $connections = (string)$server->connectionsHandler()->handle(
            $harness->request('GET', 'https://example.com/oauth/connections'),
        )->getBody();
        $this->assertStringContainsString('<td>claude.ai</td>', $connections);
        $fields = ServerHarness::formFields($connections);
        $server->connectionsHandler()->handle($harness->form('https://example.com/oauth/connections', [
            'action' => 'revoke_connection',
            'family_id' => $fields['family_id'],
            'form_token' => $fields['form_token'],
        ]));
        $this->assertSame(401, $protected($refreshed['access_token'])->getStatusCode());
        $dead = $harness->json($server->tokenHandler()->handle($harness->form('https://example.com/oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshed['refresh_token'],
            'client_id' => self::CLIENT_ID,
            'resource' => Fixtures::MCP,
        ])));
        $this->assertSame('invalid_grant', $dead['error']);

        // 9. Connecting again asks for consent again, naming the client and the scopes.
        $again = $server->authorizeHandler()->handle($harness->request('GET', $authorizeUrl));
        $this->assertSame(200, $again->getStatusCode());
        $againHtml = (string)$again->getBody();
        $this->assertStringContainsString('claude.ai wants to access Example MCP', $againHtml);
        $this->assertStringContainsString('Edit drafts', $againHtml);
        $this->assertArrayHasKey('consent_token', ServerHarness::formFields($againHtml));
    }
}
