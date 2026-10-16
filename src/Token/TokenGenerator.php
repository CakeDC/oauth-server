<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Token;

use CakeDC\OAuth\Server\Support\Base64Url;
use InvalidArgumentException;

/**
 * Random secrets: 256 bits, base64url, with a prefix that names the application and the kind.
 */
final class TokenGenerator
{
    /**
     * @param string $prefix Lowercase letters and digits, up to 16; for example the application name.
     * @throws \InvalidArgumentException
     */
    public function __construct(private readonly string $prefix = 'oauth')
    {
        if (preg_match('/^[a-z0-9]{1,16}\z/', $prefix) !== 1) {
            throw new InvalidArgumentException('The token prefix must be 1 to 16 lowercase letters or digits.');
        }
    }

    /**
     * A new access token.
     */
    public function accessToken(): string
    {
        return $this->generate('at');
    }

    /**
     * A new refresh token.
     */
    public function refreshToken(): string
    {
        return $this->generate('rt');
    }

    /**
     * A new personal access token.
     */
    public function personalToken(): string
    {
        return $this->generate('pat');
    }

    /**
     * A new authorization code.
     */
    public function authorizationCode(): string
    {
        return $this->generate('ac');
    }

    /**
     * A new client secret.
     */
    public function clientSecret(): string
    {
        return $this->generate('cs');
    }

    /**
     * A new `client_id` for registered and dynamic clients: 128 random bits in hex.
     */
    public function clientId(): string
    {
        return bin2hex(random_bytes(16));
    }

    /**
     * The stored form of a secret.
     */
    public static function hash(string $secret): string
    {
        return hash('sha256', $secret);
    }

    /**
     * `<prefix>_<kind>_<43 base64url characters>`.
     */
    private function generate(string $kind): string
    {
        return $this->prefix . '_' . $kind . '_' . Base64Url::encode(random_bytes(32));
    }
}
