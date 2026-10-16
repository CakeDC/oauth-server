<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Client\Cimd;

/**
 * A fetched HTTP response.
 */
final class FetchedResponse
{
    /**
     * @param int $status Status code.
     * @param array<string, string> $headers Lowercase name => value.
     * @param string $body Body.
     */
    public function __construct(
        public readonly int $status,
        public readonly array $headers,
        public readonly string $body,
    ) {
    }
}
