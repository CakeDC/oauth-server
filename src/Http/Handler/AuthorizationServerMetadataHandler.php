<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Http\Handler;

use CakeDC\OAuth\Server\Config\ServerConfig;
use CakeDC\OAuth\Server\Http\HttpResponder;
use CakeDC\OAuth\Server\Scope\Scopes;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Serves the authorization server metadata (RFC 8414). Mount it at ServerConfig::metadataPath().
 *
 * @internal Built through the AuthorizationServer factories, not by you: get it from the server.
 * Its constructor may change in any 1.x release.
 */
final class AuthorizationServerMetadataHandler implements RequestHandlerInterface
{
    /**
     * @param \CakeDC\OAuth\Server\Config\ServerConfig $config Settings.
     * @param \CakeDC\OAuth\Server\Http\HttpResponder $responder Responses.
     */
    public function __construct(
        private readonly ServerConfig $config,
        private readonly HttpResponder $responder,
    ) {
    }

    /**
     * @inheritDoc
     */
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        if ($request->getMethod() === 'OPTIONS') {
            return $this->responder->preflight();
        }
        if ($request->getMethod() !== 'GET') {
            return $this->responder->withCors($this->responder->methodNotAllowed('GET, OPTIONS'));
        }

        return $this->responder->withCors($this->responder->json(self::document($this->config), 200, [], 300));
    }

    /**
     * The metadata document.
     *
     * @param \CakeDC\OAuth\Server\Config\ServerConfig $config Settings.
     * @return array<string, mixed>
     */
    public static function document(ServerConfig $config): array
    {
        $clientAuth = ['none', 'client_secret_basic', 'client_secret_post'];
        $grantTypes = ['authorization_code', 'refresh_token'];
        if ($config->clientCredentials) {
            $grantTypes[] = 'client_credentials';
        }

        return array_filter([
            'issuer' => $config->issuer,
            'authorization_endpoint' => $config->endpointUrl('authorize'),
            'token_endpoint' => $config->endpointUrl('token'),
            'registration_endpoint' => $config->registrationMode === ServerConfig::REGISTRATION_CLOSED
                ? null
                : $config->endpointUrl('register'),
            'revocation_endpoint' => $config->endpointUrl('revoke'),
            'introspection_endpoint' => $config->introspection ? $config->endpointUrl('introspect') : null,
            'scopes_supported' => [...$config->resources->allScopeNames(), Scopes::OFFLINE_ACCESS],
            'response_types_supported' => ['code'],
            'response_modes_supported' => ['query'],
            'grant_types_supported' => $grantTypes,
            'token_endpoint_auth_methods_supported' => $clientAuth,
            'revocation_endpoint_auth_methods_supported' => $clientAuth,
            'introspection_endpoint_auth_methods_supported' => $config->introspection
                ? ['client_secret_basic', 'client_secret_post']
                : null,
            'code_challenge_methods_supported' => ['S256'],
            'client_id_metadata_document_supported' => $config->cimdEnabled,
            'authorization_response_iss_parameter_supported' => true,
        ], fn(mixed $value): bool => $value !== null);
    }
}
