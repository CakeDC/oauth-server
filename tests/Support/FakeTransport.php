<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Support;

use CakeDC\OAuth\Server\Client\Cimd\FetchedResponse;
use CakeDC\OAuth\Server\Client\Cimd\HttpTransportInterface;
use RuntimeException;
use Throwable;

class FakeTransport implements HttpTransportInterface
{
    /**
     * @var array<string, \CakeDC\OAuth\Server\Client\Cimd\FetchedResponse|\Throwable>
     */
    public array $responses = [];

    /**
     * @var list<array{0: string, 1: string}>
     */
    public array $requests = [];

    /**
     * Serves $document as JSON at $url.
     *
     * @param array<string, mixed> $document
     */
    public function serve(string $url, array $document, string $cacheControl = 'max-age=600'): void
    {
        $this->responses[$url] = new FetchedResponse(
            200,
            ['content-type' => 'application/json', 'cache-control' => $cacheControl],
            (string)json_encode($document),
        );
    }

    public function get(string $url, string $ip, int $timeout, int $maxBytes): FetchedResponse
    {
        $this->requests[] = [$url, $ip];
        $response = $this->responses[$url] ?? new RuntimeException('Could not resolve host');
        if ($response instanceof Throwable) {
            throw $response;
        }

        return $response;
    }
}
