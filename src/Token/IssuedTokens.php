<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Token;

use CakeDC\OAuth\Server\Scope\Scopes;

/**
 * Tokens just issued, with their values (only known at this moment).
 */
final class IssuedTokens
{
    /**
     * @param \CakeDC\OAuth\Server\Token\Token $access The stored access token.
     * @param string $accessToken Its value.
     * @param \CakeDC\OAuth\Server\Token\Token|null $refresh The stored refresh token.
     * @param string|null $refreshToken Its value.
     */
    public function __construct(
        public readonly Token $access,
        public readonly string $accessToken,
        public readonly ?Token $refresh = null,
        public readonly ?string $refreshToken = null,
    ) {
    }

    /**
     * The token response body (RFC 6749, section 5.1).
     *
     * @return array<string, mixed>
     */
    public function toResponse(): array
    {
        $expiresAt = $this->access->expiresAt ?? $this->access->createdAt;
        $body = [
            'access_token' => $this->accessToken,
            'token_type' => 'Bearer',
            'expires_in' => $expiresAt->getTimestamp() - $this->access->createdAt->getTimestamp(),
            'scope' => Scopes::format(array_values(array_unique($this->access->scopes))),
        ];
        if ($this->refreshToken !== null) {
            $body['refresh_token'] = $this->refreshToken;
        }

        return $body;
    }
}
