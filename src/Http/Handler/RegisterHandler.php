<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Http\Handler;

use CakeDC\OAuth\Server\Client\ClientRegistrar;
use CakeDC\OAuth\Server\Config\ServerConfig;
use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Http\HttpResponder;
use CakeDC\OAuth\Server\RateLimit\RateLimiter;
use Closure;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;

/**
 * Dynamic client registration (RFC 7591).
 */
final class RegisterHandler implements RequestHandlerInterface
{
    use GuardsErrors;

    private const MAX_BYTES = 16384;

    /**
     * @param \CakeDC\OAuth\Server\Config\ServerConfig $config Settings.
     * @param \CakeDC\OAuth\Server\Client\ClientRegistrar $registrar Registration.
     * @param \CakeDC\OAuth\Server\RateLimit\RateLimiter $rateLimiter Rate limiting.
     * @param \CakeDC\OAuth\Server\Http\HttpResponder $responder Responses.
     * @param \Psr\Log\LoggerInterface $logger Logger.
     * @param \Closure $clientIp `fn (ServerRequestInterface $request): string`.
     */
    public function __construct(
        private readonly ServerConfig $config,
        private readonly ClientRegistrar $registrar,
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
            if ($this->config->registrationMode === ServerConfig::REGISTRATION_CLOSED) {
                throw OAuthException::accessDenied('Dynamic client registration is disabled.');
            }
            // Throttle before checking the token so failed guesses count too.
            $this->rateLimiter->hit('register', ($this->clientIp)($request));
            if ($this->config->registrationMode === ServerConfig::REGISTRATION_TOKEN) {
                $matched = preg_match('/^Bearer\s+(\S+)\z/i', $request->getHeaderLine('Authorization'), $matches) === 1;
                if (!$matched || !hash_equals((string)$this->config->initialAccessToken, $matches[1])) {
                    throw new OAuthException(
                        'invalid_token',
                        'A valid initial access token is required.',
                        401,
                        ['WWW-Authenticate' => 'Bearer error="invalid_token"'],
                    );
                }
            }
            $type = strtolower(trim(explode(';', $request->getHeaderLine('Content-Type'))[0]));
            if ($type !== 'application/json') {
                throw OAuthException::invalidClientMetadata('Send the registration as application/json.');
            }
            $body = $this->readBody($request);
            $metadata = json_decode($body, true);
            if (!is_array($metadata) || ($metadata !== [] && array_is_list($metadata))) {
                throw OAuthException::invalidClientMetadata('The registration request is not a JSON object.');
            }
            $result = $this->registrar->register($metadata);

            $response = ClientRegistrar::registrationResponse($result['client'], $result['secret']);

            return $this->responder->json($response, 201);
        });
    }

    /**
     * Reads the body, refusing it as soon as it exceeds the limit.
     */
    private function readBody(ServerRequestInterface $request): string
    {
        $stream = $request->getBody();
        if ($stream->isSeekable()) {
            $stream->rewind();
        }
        $body = '';
        $length = 0;
        while ($length <= self::MAX_BYTES && !$stream->eof()) {
            $chunk = $stream->read(self::MAX_BYTES + 1 - $length);
            if ($chunk === '') {
                break;
            }
            $body .= $chunk;
            $length += strlen($chunk);
        }
        if (strlen($body) > self::MAX_BYTES) {
            throw OAuthException::invalidClientMetadata('The registration request is too large.');
        }

        return $body;
    }
}
