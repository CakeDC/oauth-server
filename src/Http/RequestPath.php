<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Http;

use CakeDC\OAuth\Server\Exception\OAuthException;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The request path in a form that is safe to echo into a form action or a login return URL.
 */
final class RequestPath
{
    /**
     * The request path as a single-slash absolute path, so it can never read as a protocol-relative URL;
     * control characters and backslashes are refused.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @throws \CakeDC\OAuth\Server\Exception\OAuthException When the path contains a control character or backslash.
     */
    public static function safe(ServerRequestInterface $request): string
    {
        $path = $request->getUri()->getPath();
        // Browsers drop tab, CR and LF from URLs and read a backslash as a slash.
        if (preg_match('/[\x00-\x1F\x7F\\\\]/', $path) === 1) {
            throw OAuthException::invalidRequest('The request path is not valid.');
        }

        return '/' . ltrim($path, '/');
    }
}
