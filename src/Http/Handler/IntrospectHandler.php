<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Http\Handler;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Client\ClientAuthenticator;
use CakeDC\OAuth\Server\Config\ServerConfig;
use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Http\FormBody;
use CakeDC\OAuth\Server\Http\HttpResponder;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Owner\UserProviderInterface;
use CakeDC\OAuth\Server\RateLimit\RateLimiter;
use CakeDC\OAuth\Server\Scope\Scopes;
use CakeDC\OAuth\Server\Storage\ClientRepositoryInterface;
use CakeDC\OAuth\Server\Storage\TokenRepositoryInterface;
use CakeDC\OAuth\Server\Token\Token;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use CakeDC\OAuth\Server\Token\TokenType;
use CakeDC\OAuth\Server\Token\TokenValidator;
use CakeDC\OAuth\Server\Token\ValidatedToken;
use Closure;
use InvalidArgumentException;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;

/**
 * Token introspection (RFC 7662), for other services that need to check this server's tokens.
 */
final class IntrospectHandler implements RequestHandlerInterface
{
    use GuardsErrors;

    /**
     * @internal Build it through the AuthorizationServer; its constructor may change in any 1.x release.
     * @param \CakeDC\OAuth\Server\Config\ServerConfig $config Settings.
     * @param \CakeDC\OAuth\Server\Client\ClientAuthenticator $clientAuthenticator Client authentication.
     * @param \CakeDC\OAuth\Server\Storage\TokenRepositoryInterface $tokens Tokens.
     * @param \CakeDC\OAuth\Server\Storage\ClientRepositoryInterface $clients Clients.
     * @param \CakeDC\OAuth\Server\Token\TokenValidator $validator Validation.
     * @param \CakeDC\OAuth\Server\RateLimit\RateLimiter $rateLimiter Rate limiting.
     * @param \CakeDC\OAuth\Server\Http\HttpResponder $responder Responses.
     * @param \Psr\Clock\ClockInterface $clock Clock.
     * @param \Psr\Log\LoggerInterface $logger Logger.
     * @param \Closure $clientIp `fn (ServerRequestInterface $request): string`.
     * @param \CakeDC\OAuth\Server\Owner\UserProviderInterface $users The application's people.
     */
    public function __construct(
        private readonly ServerConfig $config,
        private readonly ClientAuthenticator $clientAuthenticator,
        private readonly TokenRepositoryInterface $tokens,
        private readonly ClientRepositoryInterface $clients,
        private readonly TokenValidator $validator,
        private readonly RateLimiter $rateLimiter,
        private readonly HttpResponder $responder,
        private readonly ClockInterface $clock,
        private readonly LoggerInterface $logger,
        private readonly Closure $clientIp,
        private readonly UserProviderInterface $users,
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

        return $this->guarded(function () use ($request): ResponseInterface {
            if (!$this->config->introspection) {
                throw OAuthException::accessDenied('Token introspection is disabled.');
            }
            if ($request->getMethod() !== 'POST') {
                return $this->responder->methodNotAllowed('POST, OPTIONS');
            }
            $this->rateLimiter->hit('token', ($this->clientIp)($request));
            if (!FormBody::isForm($request)) {
                throw OAuthException::invalidRequest(
                    'Send the parameters form-encoded (application/x-www-form-urlencoded).',
                );
            }
            [$body, $repeated] = FormBody::read($request);
            if (in_array('token', $repeated, true)) {
                throw OAuthException::invalidRequest('"token" was sent more than once.');
            }
            $client = $this->clientAuthenticator->authenticate($request, $body, ($this->clientIp)($request));
            if ($client->isPublic() || !$client->allowIntrospection) {
                throw OAuthException::invalidClient('This client may not introspect tokens.');
            }
            $token = $body['token'] ?? '';
            if ($token === '') {
                throw OAuthException::invalidRequest('"token" is missing.');
            }

            return $this->responder->json($this->introspect($token));
        });
    }

    /**
     * The introspection response for $value.
     *
     * @return array<string, mixed>
     */
    private function introspect(string $value): array
    {
        $inactive = ['active' => false];
        $stored = $this->tokens->findTokenByHash(TokenGenerator::hash($value));
        if ($stored === null) {
            return $inactive;
        }
        if ($stored->type === TokenType::Refresh) {
            $client = $stored->clientInternalId === null
                ? null
                : $this->clients->findClientById($stored->clientInternalId);
            $dead = !$stored->isActive($this->clock->now()) || $stored->usedAt !== null;
            if ($dead || $client === null || $client->isRevoked() || !$this->ownerExists($stored, $client)) {
                return $inactive;
            }

            return array_filter([
                'active' => true,
                'scope' => Scopes::format($stored->scopes),
                'client_id' => $client->clientId,
                'sub' => $stored->subject,
                'aud' => $stored->resource,
                'exp' => $stored->expiresAt?->getTimestamp(),
                'iat' => $stored->createdAt->getTimestamp(),
                'token_type' => 'refresh_token',
            ], fn(mixed $item): bool => $item !== null);
        }
        try {
            $result = $this->validator->validate($value, $stored->resource, false);
        } catch (InvalidArgumentException) {
            return $inactive;
        }
        if (!$result instanceof ValidatedToken) {
            return $inactive;
        }

        return array_filter([
            'active' => true,
            'scope' => Scopes::format($result->scopes),
            'client_id' => $result->client?->clientId,
            'sub' => $result->token->subject,
            'username' => $result->owner->displayName,
            'aud' => $result->resource->identifier,
            'exp' => $result->token->expiresAt?->getTimestamp(),
            'iat' => $result->token->createdAt->getTimestamp(),
            'token_type' => 'Bearer',
        ], fn(mixed $item): bool => $item !== null);
    }

    /**
     * Whether the person (or client identity) a refresh token belongs to still exists.
     */
    private function ownerExists(Token $token, Client $client): bool
    {
        if ($token->subjectType === SubjectType::User) {
            return $this->users->findBySubject($token->subject) !== null;
        }
        $resource = $this->config->resources->get($token->resource);

        return $resource !== null && $this->users->forClient($client, $resource) !== null;
    }
}
