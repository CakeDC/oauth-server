<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Http\Handler;

use CakeDC\OAuth\Server\Client\ClientAuthenticator;
use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Http\FormBody;
use CakeDC\OAuth\Server\Http\HttpResponder;
use CakeDC\OAuth\Server\RateLimit\RateLimiter;
use CakeDC\OAuth\Server\Token\TokenRevoker;
use Closure;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;

/**
 * Token revocation (RFC 7009).
 */
final class RevokeHandler implements RequestHandlerInterface
{
    use GuardsErrors;

    /**
     * @param \CakeDC\OAuth\Server\Client\ClientAuthenticator $clientAuthenticator Client authentication.
     * @param \CakeDC\OAuth\Server\Token\TokenRevoker $revoker Revoker.
     * @param \CakeDC\OAuth\Server\RateLimit\RateLimiter $rateLimiter Rate limiting.
     * @param \CakeDC\OAuth\Server\Http\HttpResponder $responder Responses.
     * @param \Psr\Log\LoggerInterface $logger Logger.
     * @param \Closure $clientIp `fn (ServerRequestInterface $request): string`.
     */
    public function __construct(
        private readonly ClientAuthenticator $clientAuthenticator,
        private readonly TokenRevoker $revoker,
        private readonly RateLimiter $rateLimiter,
        private readonly HttpResponder $responder,
        private readonly LoggerInterface $logger,
        private readonly Closure $clientIp,
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
            if ($repeated !== []) {
                throw OAuthException::invalidRequest(sprintf('"%s" was sent more than once.', $repeated[0]));
            }
            $token = $body['token'] ?? '';
            if ($token === '') {
                throw OAuthException::invalidRequest('"token" is missing.');
            }
            $client = $this->clientAuthenticator->authenticate($request, $body);
            $this->revoker->revokeForClient($client, $token);

            return $this->responder->json([]);
        });
    }
}
