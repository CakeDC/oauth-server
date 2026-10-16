<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Support;

use Nyholm\Psr7\Uri;
use Psr\Http\Message\UriInterface;

/**
 * A URI that returns its path exactly as it arrived, `//host/...` included. Nyholm collapses leading
 * slashes in getPath(); other PSR-7 implementations (Guzzle, Laminas) return them as they are.
 */
final class RawPathUri implements UriInterface
{
    private Uri $uri;

    public function __construct(string $uri, private readonly string $path)
    {
        $this->uri = new Uri($uri);
    }

    public function getScheme(): string
    {
        return $this->uri->getScheme();
    }

    public function getAuthority(): string
    {
        return $this->uri->getAuthority();
    }

    public function getUserInfo(): string
    {
        return $this->uri->getUserInfo();
    }

    public function getHost(): string
    {
        return $this->uri->getHost();
    }

    public function getPort(): ?int
    {
        return $this->uri->getPort();
    }

    public function getPath(): string
    {
        return $this->path;
    }

    public function getQuery(): string
    {
        return $this->uri->getQuery();
    }

    public function getFragment(): string
    {
        return $this->uri->getFragment();
    }

    public function withScheme(string $scheme): UriInterface
    {
        return $this->uri->withScheme($scheme);
    }

    public function withUserInfo(string $user, ?string $password = null): UriInterface
    {
        return $this->uri->withUserInfo($user, $password);
    }

    public function withHost(string $host): UriInterface
    {
        return $this->uri->withHost($host);
    }

    public function withPort(?int $port): UriInterface
    {
        return $this->uri->withPort($port);
    }

    public function withPath(string $path): UriInterface
    {
        return new self((string)$this->uri, $path);
    }

    public function withQuery(string $query): UriInterface
    {
        return $this->uri->withQuery($query);
    }

    public function withFragment(string $fragment): UriInterface
    {
        return $this->uri->withFragment($fragment);
    }

    public function __toString(): string
    {
        return (string)$this->uri;
    }
}
