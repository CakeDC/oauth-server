<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Http\Handler;

use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use PHPUnit\Framework\TestCase;

class AuthorizationServerMetadataHandlerTest extends TestCase
{
    public function testPublishesTheRfc8414Document(): void
    {
        $harness = new ServerHarness();

        $response = $harness->server->metadataHandler()->handle(
            $harness->request('GET', 'https://example.com/.well-known/oauth-authorization-server'),
        );
        $document = $harness->json($response);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('*', $response->getHeaderLine('Access-Control-Allow-Origin'));
        $this->assertSame('public, max-age=300', $response->getHeaderLine('Cache-Control'));
        $this->assertSame([
            'issuer' => 'https://example.com',
            'authorization_endpoint' => 'https://example.com/oauth/authorize',
            'token_endpoint' => 'https://example.com/oauth/token',
            'registration_endpoint' => 'https://example.com/oauth/register',
            'revocation_endpoint' => 'https://example.com/oauth/revoke',
            'introspection_endpoint' => 'https://example.com/oauth/introspect',
            'scopes_supported' => ['content:read', 'content:write', 'content:publish', 'api', 'offline_access'],
            'response_types_supported' => ['code'],
            'response_modes_supported' => ['query'],
            'grant_types_supported' => ['authorization_code', 'refresh_token', 'client_credentials'],
            'token_endpoint_auth_methods_supported' => ['none', 'client_secret_basic', 'client_secret_post'],
            'revocation_endpoint_auth_methods_supported' => ['none', 'client_secret_basic', 'client_secret_post'],
            'introspection_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post'],
            'code_challenge_methods_supported' => ['S256'],
            'client_id_metadata_document_supported' => true,
            'authorization_response_iss_parameter_supported' => true,
        ], $document);
    }

    public function testLeavesOutDisabledFeatures(): void
    {
        $harness = new ServerHarness([
            'registration' => ['mode' => 'closed'],
            'introspection' => false,
            'clientCredentials' => false,
            'cimd' => ['enabled' => false],
        ]);

        $document = $harness->json($harness->server->metadataHandler()->handle($harness->request('GET', '/')));

        $this->assertArrayNotHasKey('registration_endpoint', $document);
        $this->assertArrayNotHasKey('introspection_endpoint', $document);
        $this->assertArrayNotHasKey('introspection_endpoint_auth_methods_supported', $document);
        $this->assertSame(['authorization_code', 'refresh_token'], $document['grant_types_supported']);
        $this->assertFalse($document['client_id_metadata_document_supported']);
    }

    public function testPreflightAndMethods(): void
    {
        $harness = new ServerHarness();
        $handler = $harness->server->metadataHandler();

        $this->assertSame(204, $handler->handle($harness->request('OPTIONS', '/'))->getStatusCode());
        $this->assertSame(405, $handler->handle($harness->request('POST', '/'))->getStatusCode());
    }
}
