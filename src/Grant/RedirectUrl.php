<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Grant;

/**
 * Builds the redirect back to a client.
 */
final class RedirectUrl
{
    /**
     * $uri with $params appended to its query; null values are left out.
     *
     * @param array<string, string|null> $params Parameters.
     */
    public static function build(string $uri, array $params): string
    {
        $query = http_build_query(
            array_filter($params, fn(?string $value): bool => $value !== null),
            '',
            '&',
            PHP_QUERY_RFC3986,
        );

        return $uri . (str_contains($uri, '?') ? '&' : '?') . $query;
    }
}
