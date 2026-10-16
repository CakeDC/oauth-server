<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Scope;

use CakeDC\OAuth\Server\Exception\OAuthException;

/**
 * Parsing and formatting of space-delimited scope strings (RFC 6749, section 3.3).
 */
final class Scopes
{
    public const OFFLINE_ACCESS = 'offline_access';

    /**
     * Splits a scope string into unique scope tokens, in order.
     *
     * @return list<string>
     * @throws \CakeDC\OAuth\Server\Exception\OAuthException invalid_scope for a malformed token.
     */
    public static function parse(?string $scope): array
    {
        if ($scope === null || trim($scope) === '') {
            return [];
        }
        $tokens = preg_split('/ +/', trim($scope)) ?: [];
        foreach ($tokens as $token) {
            if (!self::isValid($token)) {
                throw OAuthException::invalidScope(sprintf('"%s" is not a valid scope.', $token));
            }
        }

        return array_values(array_unique($tokens));
    }

    /**
     * Joins scopes with single spaces.
     *
     * @param list<string> $scopes Scopes.
     */
    public static function format(array $scopes): string
    {
        return implode(' ', $scopes);
    }

    /**
     * Whether $scope is a scope-token: printable ASCII except space, `"` and `\`.
     */
    public static function isValid(string $scope): bool
    {
        return preg_match('/^[\x21\x23-\x5B\x5D-\x7E]+\z/', $scope) === 1;
    }
}
