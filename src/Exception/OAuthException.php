<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Exception;

use RuntimeException;

/**
 * An OAuth error: the error code, its description and the HTTP status to answer with.
 */
final class OAuthException extends RuntimeException
{
    /**
     * @param string $error The OAuth error code.
     * @param string $description For the client developer; sent as `error_description`.
     * @param int $status HTTP status of a JSON error response.
     * @param array<string, string> $headers Extra response headers.
     */
    public function __construct(
        public readonly string $error,
        string $description,
        public readonly int $status = 400,
        public readonly array $headers = [],
    ) {
        parent::__construct($description);
    }

    /**
     * The JSON error body (RFC 6749, section 5.2).
     *
     * @return array{error: string, error_description: string}
     */
    public function toArray(): array
    {
        return ['error' => $this->error, 'error_description' => $this->getMessage()];
    }

    /**
     * A missing, repeated or malformed parameter.
     */
    public static function invalidRequest(string $description): self
    {
        return new self('invalid_request', $description);
    }

    /**
     * Client authentication failed; with Basic credentials the response challenges for them.
     */
    public static function invalidClient(string $description, bool $basic = false): self
    {
        $headers = $basic ? ['WWW-Authenticate' => 'Basic realm="oauth"'] : [];

        return new self('invalid_client', $description, 401, $headers);
    }

    /**
     * An invalid, expired, used or foreign code or refresh token.
     */
    public static function invalidGrant(string $description): self
    {
        return new self('invalid_grant', $description);
    }

    /**
     * The client may not use this grant or flow.
     */
    public static function unauthorizedClient(string $description): self
    {
        return new self('unauthorized_client', $description);
    }

    /**
     * An unknown `grant_type`.
     */
    public static function unsupportedGrantType(string $description): self
    {
        return new self('unsupported_grant_type', $description);
    }

    /**
     * An unknown `response_type`.
     */
    public static function unsupportedResponseType(string $description): self
    {
        return new self('unsupported_response_type', $description);
    }

    /**
     * An unknown scope, or none that can be granted.
     */
    public static function invalidScope(string $description): self
    {
        return new self('invalid_scope', $description);
    }

    /**
     * An unknown or mismatched `resource` (RFC 8707).
     */
    public static function invalidTarget(string $description): self
    {
        return new self('invalid_target', $description);
    }

    /**
     * The person or the server refused.
     */
    public static function accessDenied(string $description): self
    {
        return new self('access_denied', $description, 403);
    }

    /**
     * Invalid registration metadata (RFC 7591).
     */
    public static function invalidClientMetadata(string $description): self
    {
        return new self('invalid_client_metadata', $description);
    }

    /**
     * An invalid redirect URI in a registration (RFC 7591).
     */
    public static function invalidRedirectUri(string $description): self
    {
        return new self('invalid_redirect_uri', $description);
    }

    /**
     * An invalid access token presented to a protected resource or a registration endpoint.
     */
    public static function invalidToken(string $description): self
    {
        return new self('invalid_token', $description, 401);
    }

    /**
     * An unexpected failure; the description never carries internals.
     */
    public static function serverError(string $description = 'The server could not complete the request.'): self
    {
        return new self('server_error', $description, 500);
    }

    /**
     * Too many requests from one address.
     */
    public static function rateLimited(int $retryAfter): self
    {
        return new self(
            'temporarily_unavailable',
            'Too many requests. Try again later.',
            429,
            ['Retry-After' => (string)max(1, $retryAfter)],
        );
    }
}
