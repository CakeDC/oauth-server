<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Http\Middleware;

use CakeDC\OAuth\Server\Http\HttpResponder;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Token\TokenValidator;
use CakeDC\OAuth\Server\Token\ValidatedToken;
use CakeDC\OAuth\Server\Token\ValidationFailure;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Protects any PSR-15 route with this server's tokens. The next handler finds the validated token
 * and its owner in the request attributes `ValidatedToken::class` and `ResourceOwner::class`.
 *
 * CORS preflights (OPTIONS with an `Access-Control-Request-Method` header) reach the handler unauthenticated and
 * without those attributes, so the handler must answer them without side effects. Any other OPTIONS request is
 * challenged like every other request. Hosts must put their CORS layer outside this middleware and expose the
 * `WWW-Authenticate` header.
 */
final class BearerTokenMiddleware implements MiddlewareInterface
{
    /**
     * @param \CakeDC\OAuth\Server\Token\TokenValidator $validator Validation.
     * @param \CakeDC\OAuth\Server\Http\HttpResponder $responder Responses.
     * @param string $resource The resource this route belongs to.
     * @param string|null $resourceMetadataUrl Protected resource metadata (RFC 9728), named in challenges.
     * @param list<string> $requiredScopes Scopes every request needs.
     */
    public function __construct(
        private readonly TokenValidator $validator,
        private readonly HttpResponder $responder,
        private readonly string $resource,
        private readonly ?string $resourceMetadataUrl = null,
        private readonly array $requiredScopes = [],
    ) {
    }

    /**
     * @inheritDoc
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if ($request->getMethod() === 'OPTIONS' && $request->getHeaderLine('Access-Control-Request-Method') !== '') {
            return $handler->handle($request);
        }
        $authorization = $request->getHeaderLine('Authorization');
        $isBearer = preg_match('/^Bearer(?: |\z)/i', $authorization) === 1;
        if (!$isBearer || preg_match('/^Bearer *\z/i', $authorization) === 1) {
            return $this->challenge(401, null, 'A bearer token is required.', $this->requiredScopes);
        }
        if (preg_match('/^Bearer +([A-Za-z0-9\-._~+\/]+=*) *\z/i', $authorization, $matches) !== 1) {
            return $this->challenge(400, 'invalid_request', 'Malformed Authorization header.');
        }
        $result = $this->validator->validate($matches[1], $this->resource);
        if ($result instanceof ValidationFailure) {
            return $this->challenge(401, $result->error, $result->description);
        }
        if (array_diff($this->requiredScopes, $result->scopes) !== []) {
            return $this->challenge(
                403,
                'insufficient_scope',
                'The access token lacks a required scope.',
                $this->requiredScopes,
            );
        }

        $request = $request
            ->withAttribute(ValidatedToken::class, $result)
            ->withAttribute(ResourceOwner::class, $result->owner);

        return $handler->handle($request);
    }

    /**
     * An error response with its `WWW-Authenticate` challenge.
     *
     * @param int $status HTTP status.
     * @param string|null $error Error code; null when no token was presented.
     * @param string $description Human readable description.
     * @param list<string> $scopes Scopes to name.
     */
    private function challenge(int $status, ?string $error, string $description, array $scopes = []): ResponseInterface
    {
        $parts = [];
        if ($this->resourceMetadataUrl !== null) {
            $parts[] = 'resource_metadata="' . self::quote($this->resourceMetadataUrl) . '"';
        }
        if ($scopes !== []) {
            $parts[] = 'scope="' . self::quote(implode(' ', $scopes)) . '"';
        }
        $body = [];
        if ($error !== null) {
            $parts[] = 'error="' . self::quote($error) . '"';
            $parts[] = 'error_description="' . self::quote($description) . '"';
            $body = ['error' => $error, 'error_description' => $description];
        }

        return $this->responder->json($body, $status, [
            'WWW-Authenticate' => 'Bearer' . ($parts === [] ? '' : ' ' . implode(', ', $parts)),
        ]);
    }

    /**
     * A quoted-string value without control characters (RFC 9110, section 5.6.4).
     */
    private static function quote(string $value): string
    {
        return str_replace(['\\', '"'], ['\\\\', '\\"'], preg_replace('/[\x00-\x1F\x7F]/', '', $value) ?? '');
    }
}
