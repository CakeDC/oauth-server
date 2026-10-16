<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Client\Cimd;

/**
 * Fetches client metadata documents.
 */
interface HttpTransportInterface
{
    /**
     * GETs $url connecting to $ip whatever DNS says, without following redirects.
     *
     * @throws \RuntimeException On network errors, timeouts or a body over $maxBytes.
     */
    public function get(string $url, string $ip, int $timeout, int $maxBytes): FetchedResponse;
}
