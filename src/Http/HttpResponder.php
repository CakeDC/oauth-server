<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Http;

use CakeDC\OAuth\Server\Exception\OAuthException;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use stdClass;

/**
 * Builds the server's responses.
 */
final class HttpResponder
{
    private const PAGE_CSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'";

    /**
     * @param \Psr\Http\Message\ResponseFactoryInterface $responses Response factory.
     * @param \Psr\Http\Message\StreamFactoryInterface $streams Stream factory.
     */
    public function __construct(
        private readonly ResponseFactoryInterface $responses,
        private readonly StreamFactoryInterface $streams,
    ) {
    }

    /**
     * A JSON response, never cached unless $cacheSeconds is positive.
     *
     * @param array<string, mixed> $data Body.
     * @param int $status Status.
     * @param array<string, string> $headers Extra headers.
     * @param int $cacheSeconds Public cache time.
     */
    public function json(array $data, int $status = 200, array $headers = [], int $cacheSeconds = 0): ResponseInterface
    {
        $body = json_encode(
            $data === [] ? new stdClass() : $data,
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE,
        );
        $response = $this->responses->createResponse($status)
            ->withHeader('Content-Type', 'application/json')
            ->withBody($this->streams->createStream($body));
        $response = $cacheSeconds > 0
            ? $response->withHeader('Cache-Control', 'public, max-age=' . $cacheSeconds)
            : $response->withHeader('Cache-Control', 'no-store')->withHeader('Pragma', 'no-cache');
        foreach ($headers as $name => $value) {
            $response = $response->withHeader($name, $value);
        }

        return $response;
    }

    /**
     * The JSON response of an OAuth error: only `error`, `error_description` and the exception's headers.
     */
    public function error(OAuthException $error): ResponseInterface
    {
        return $this->json($error->toArray(), $error->status, $error->headers);
    }

    /**
     * A redirect.
     */
    public function redirect(string $url, int $status = 302): ResponseInterface
    {
        return $this->responses->createResponse($status)
            ->withHeader('Location', $url)
            ->withHeader('Cache-Control', 'no-store');
    }

    /**
     * An HTML page that cannot be framed or cached and does not leak its URL in a Referer.
     *
     * @param string $html The page.
     * @param int $status Status.
     * @param array<string, string> $headers Extra headers.
     */
    public function page(string $html, int $status = 200, array $headers = []): ResponseInterface
    {
        $response = $this->responses->createResponse($status)
            ->withHeader('Content-Type', 'text/html; charset=utf-8')
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('X-Frame-Options', 'DENY')
            ->withHeader('Content-Security-Policy', self::PAGE_CSP)
            ->withHeader('Referrer-Policy', 'no-referrer')
            ->withHeader('X-Content-Type-Options', 'nosniff')
            ->withBody($this->streams->createStream($html));
        foreach ($headers as $name => $value) {
            $response = $response->withHeader($name, $value);
        }

        return $response;
    }

    /**
     * $response readable by browser-based clients (any origin, no credentials).
     */
    public function withCors(ResponseInterface $response): ResponseInterface
    {
        return $response
            ->withHeader('Access-Control-Allow-Origin', '*')
            ->withHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
            ->withHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type, MCP-Protocol-Version')
            ->withHeader('Access-Control-Max-Age', '86400');
    }

    /**
     * The answer to a CORS preflight.
     */
    public function preflight(): ResponseInterface
    {
        return $this->withCors($this->responses->createResponse(204));
    }

    /**
     * 405 with the allowed methods.
     */
    public function methodNotAllowed(string $allow): ResponseInterface
    {
        return $this->json(
            ['error' => 'invalid_request', 'error_description' => 'Method not allowed.'],
            405,
            ['Allow' => $allow],
        );
    }
}
