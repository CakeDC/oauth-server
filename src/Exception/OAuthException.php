<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Exception;

use InvalidArgumentException;
use RuntimeException;

/**
 * An OAuth error: the error code, its description and the HTTP status to answer with.
 */
final class OAuthException extends RuntimeException
{
    /**
     * The characters RFC 6749 (sections 4.1.2.1 and 5.2) and RFC 6750 (section 3) allow in
     * `error_description`: %x20-21 / %x23-5B / %x5D-7E, so printable ASCII without `"` and `\`.
     */
    private const DESCRIPTION = '/\A[\x20\x21\x23-\x5B\x5D-\x7E]*\z/';

    /**
     * The longest part of a request value that printable() keeps.
     */
    private const PRINTABLE_LENGTH = 64;

    /**
     * @param string $error The OAuth error code.
     * @param string $description For the client developer; sent as `error_description`. Printable ASCII
     *   without `"` and `\` (see isValidDescription()); put a value from the request through printable().
     * @param int $status HTTP status of a JSON error response.
     * @param array<string, string> $headers Extra response headers.
     * @param bool $temporary Whether the failure is a temporary unavailability of something the server
     *   depends on (for example a client metadata host), so a cached answer may stand in.
     * @throws \InvalidArgumentException When $description has a character the RFCs do not allow.
     */
    public function __construct(
        public readonly string $error,
        string $description,
        public readonly int $status = 400,
        public readonly array $headers = [],
        public readonly bool $temporary = false,
    ) {
        if (!self::isValidDescription($description)) {
            throw new InvalidArgumentException(
                'An error_description may only contain printable ASCII characters other than " and \\.',
            );
        }
        parent::__construct($description);
    }

    /**
     * Whether $description fits `error_description`: %x20-21 / %x23-5B / %x5D-7E (RFC 6749 sections 4.1.2.1
     * and 5.2, RFC 6750 section 3), that is printable ASCII without a double quote or a backslash.
     */
    public static function isValidDescription(string $description): bool
    {
        return preg_match(self::DESCRIPTION, $description) === 1;
    }

    /**
     * A value taken from the request (a parameter name, a grant type, a scope) made fit for a description:
     * every byte outside the allowed set becomes `?`, and it is cut to $max characters (64 by default).
     *
     * @internal Used by the library to build its own descriptions.
     */
    public static function printable(string $value, int $max = self::PRINTABLE_LENGTH): string
    {
        $printable = (string)preg_replace('/[^\x20\x21\x23-\x5B\x5D-\x7E]/', '?', $value);

        return strlen($printable) > $max ? substr($printable, 0, max(0, $max)) . '...' : $printable;
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
     * The client could not be checked right now (network error, timeout, HTTP 5xx or 429). Same answer as
     * invalidClient() for the client, but flagged so a stored copy of the client may be used instead.
     */
    public static function clientUnavailable(string $description): self
    {
        return new self('invalid_client', $description, 401, [], true);
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
