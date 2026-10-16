<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Client\Cimd;

use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Support\HostName;
use InvalidArgumentException;
use RuntimeException;

/**
 * Fetches and checks Client ID Metadata Documents: the client_id is an https URL serving the
 * client's metadata.
 */
final class MetadataDocumentFetcher
{
    /**
     * RFC 3986 URI characters only: no backslashes, whitespace, control or non-ASCII characters, so parse_url
     * and the HTTP client cannot disagree on the host.
     */
    public const URL_CHARACTERS = '/^[A-Za-z0-9\-._~:\/?\[\]@!$&\'()*+,;=%]+\z/';

    /**
     * @param \CakeDC\OAuth\Server\Client\Cimd\DnsResolverInterface $dns Resolver.
     * @param \CakeDC\OAuth\Server\Client\Cimd\HttpTransportInterface $transport Transport.
     * @param int $timeout Seconds.
     * @param int $maxBytes Largest accepted document.
     * @param list<string>|null $allowedHosts Only these client_id hosts; null for any.
     */
    public function __construct(
        private readonly DnsResolverInterface $dns,
        private readonly HttpTransportInterface $transport,
        private readonly int $timeout = 5,
        private readonly int $maxBytes = 10240,
        private readonly ?array $allowedHosts = null,
    ) {
        if ($timeout < 1 || $maxBytes < 1) {
            throw new InvalidArgumentException('The timeout and the maximum size must be at least 1.');
        }
    }

    /**
     * Whether $clientId is a URL-formatted client id.
     */
    public static function isMetadataDocumentId(string $clientId): bool
    {
        return str_starts_with($clientId, 'https://') && self::parse($clientId) !== null;
    }

    /**
     * Whether the current host policy accepts $clientId: a clean https URL whose host is allowed (when
     * `allowedHosts` is set). Cached clients are held to it as well, so a policy change takes effect at once.
     */
    public function allowsClientId(string $clientId): bool
    {
        $parts = self::parse($clientId);

        return $parts !== null && $this->hostAllowed(strtolower((string)$parts['host']));
    }

    /**
     * Whether $host (lower case) passes the allowed hosts.
     */
    private function hostAllowed(string $host): bool
    {
        return $this->allowedHosts === null
            || in_array($host, array_map('strtolower', $this->allowedHosts), true);
    }

    /**
     * Fetches and checks the document of $clientId.
     *
     * @return array{document: array<string, mixed>, maxAge: int|null}
     * @throws \CakeDC\OAuth\Server\Exception\OAuthException invalid_client.
     */
    public function fetch(string $clientId): array
    {
        $parts = self::parse($clientId);
        if ($parts === null) {
            throw OAuthException::invalidClient('The client_id is not a valid metadata document URL.');
        }
        $host = strtolower((string)$parts['host']);
        if (!$this->hostAllowed($host)) {
            throw OAuthException::invalidClient(sprintf('Clients from %s are not accepted.', $host));
        }
        $literal = trim($host, '[]');
        $addresses = filter_var($literal, FILTER_VALIDATE_IP) !== false ? [$literal] : $this->dns->resolve($host);
        if ($addresses === []) {
            throw OAuthException::invalidClient('The client_id host does not resolve.');
        }
        foreach ($addresses as $address) {
            if (!IpGuard::isPublic($address)) {
                throw OAuthException::invalidClient('The client_id host resolves to a non-public address.');
            }
        }
        try {
            $response = $this->transport->get($clientId, $addresses[0], $this->timeout, $this->maxBytes);
        } catch (RuntimeException $e) {
            throw OAuthException::clientUnavailable('The client metadata document could not be fetched.');
        }
        if ($response->status !== 200) {
            $temporary = $response->status >= 500 || $response->status === 429;
            throw ($temporary ? OAuthException::clientUnavailable(...) : OAuthException::invalidClient(...))(
                sprintf('The client metadata document answered HTTP %d.', $response->status),
            );
        }
        $mediaType = strtolower(trim(explode(';', $response->headers['content-type'] ?? '')[0]));
        if ($mediaType !== 'application/json') {
            throw OAuthException::invalidClient('The client metadata document must be application/json.');
        }
        $document = json_decode($response->body, true);
        if (!is_array($document) || array_is_list($document)) {
            throw OAuthException::invalidClient('The client metadata document is not a JSON object.');
        }
        self::check($document, $clientId);

        /** @var array<string, mixed> $document */
        return ['document' => $document, 'maxAge' => self::maxAge($response->headers['cache-control'] ?? null)];
    }

    /**
     * The parts of a clean https client_id URL, or null: only URI characters, a strict host, no userinfo,
     * fragment, empty or dot-segment path.
     *
     * @return array<string, mixed>|null
     */
    private static function parse(string $clientId): ?array
    {
        if (preg_match(self::URL_CHARACTERS, $clientId) !== 1 || str_contains($clientId, '#')) {
            return null;
        }
        $parts = parse_url($clientId);
        if (
            !is_array($parts)
            || ($parts['scheme'] ?? '') !== 'https'
            || !isset($parts['host'])
            || !HostName::isValid($parts['host'])
            || isset($parts['user'])
            || isset($parts['pass'])
        ) {
            return null;
        }
        $path = $parts['path'] ?? '';
        if ($path === '' || $path === '/') {
            return null;
        }
        foreach (explode('/', $path) as $segment) {
            if (in_array(rawurldecode($segment), ['.', '..'], true)) {
                return null;
            }
        }

        return $parts;
    }

    /**
     * Checks the fields the MCP specification requires.
     *
     * @param array<mixed> $document Document.
     * @throws \CakeDC\OAuth\Server\Exception\OAuthException
     */
    private static function check(array $document, string $clientId): void
    {
        if (($document['client_id'] ?? null) !== $clientId) {
            throw OAuthException::invalidClient('The metadata document client_id does not match its URL.');
        }
        $name = $document['client_name'] ?? null;
        if (!is_string($name) || trim($name) === '') {
            throw OAuthException::invalidClient('The metadata document needs a client_name.');
        }
        $redirectUris = $document['redirect_uris'] ?? null;
        if (!is_array($redirectUris) || $redirectUris === [] || !array_is_list($redirectUris)) {
            throw OAuthException::invalidClient('The metadata document needs redirect_uris.');
        }
        foreach ($redirectUris as $uri) {
            if (!is_string($uri)) {
                throw OAuthException::invalidClient('The metadata document redirect_uris must be strings.');
            }
        }
        if (($document['token_endpoint_auth_method'] ?? 'none') !== 'none') {
            throw OAuthException::invalidClient(
                'Only public metadata document clients (token_endpoint_auth_method "none") are supported.',
            );
        }
    }

    /**
     * Seconds the document may be cached: 0 for no-store or no-cache, null without max-age.
     */
    private static function maxAge(?string $cacheControl): ?int
    {
        if ($cacheControl === null) {
            return null;
        }
        $cacheControl = strtolower($cacheControl);
        if (str_contains($cacheControl, 'no-store') || str_contains($cacheControl, 'no-cache')) {
            return 0;
        }
        if (preg_match('/(?:\A|[,\s])max-age=(\d{1,10})(?:\z|[,\s;])/', $cacheControl, $matches) === 1) {
            return (int)$matches[1];
        }

        return null;
    }
}
