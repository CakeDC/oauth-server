<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Http;

use CakeDC\OAuth\Server\Exception\OAuthException;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Client credentials in an `Authorization: Basic` header (RFC 6749, section 2.3.1).
 */
final class BasicCredentials
{
    /**
     * The client id and secret, form-decoded, or null without a Basic header.
     *
     * @return array{0: string, 1: string}|null
     * @throws \CakeDC\OAuth\Server\Exception\OAuthException invalid_client for a malformed header.
     */
    public static function fromRequest(ServerRequestInterface $request): ?array
    {
        $header = $request->getHeaderLine('Authorization');
        if (strncasecmp($header, 'Basic ', 6) !== 0) {
            return null;
        }
        $decoded = base64_decode(trim(substr($header, 6)), true);
        if ($decoded === false || !str_contains($decoded, ':')) {
            throw OAuthException::invalidClient('Malformed Basic credentials.', true);
        }
        [$clientId, $secret] = explode(':', $decoded, 2);

        return [urldecode($clientId), urldecode($secret)];
    }
}
