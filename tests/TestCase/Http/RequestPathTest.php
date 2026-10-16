<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Http;

use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Http\RequestPath;
use CakeDC\OAuth\Server\Test\Support\RawPathUri;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class RequestPathTest extends TestCase
{
    /**
     * @return array<string, array{string, string}>
     */
    public static function paths(): array
    {
        return [
            'protocol relative' => ['//evil.example/oauth/authorize', '/evil.example/oauth/authorize'],
            'three slashes' => ['///evil.example/x', '/evil.example/x'],
            'plain' => ['/oauth/authorize', '/oauth/authorize'],
            'empty' => ['', '/'],
            'relative' => ['oauth/authorize', '/oauth/authorize'],
        ];
    }

    /**
     * The path becomes a login return URL and a form action: it must never read as `//host`, whatever
     * the PSR-7 implementation returns from getPath().
     */
    #[DataProvider('paths')]
    public function testTheSafePathStartsWithExactlyOneSlash(string $raw, string $expected): void
    {
        $request = (new ServerRequest('GET', 'https://example.com/'))
            ->withUri(new RawPathUri('https://example.com/', $raw), true);

        $this->assertSame($expected, RequestPath::safe($request));
    }

    public function testControlCharactersAndBackslashesAreRefused(): void
    {
        foreach (["/a\tb", '/a\\b', '/\\\\evil.example'] as $raw) {
            $request = (new ServerRequest('GET', 'https://example.com/'))
                ->withUri(new RawPathUri('https://example.com/', $raw), true);
            try {
                RequestPath::safe($request);
                $this->fail('Accepted ' . json_encode($raw));
            } catch (OAuthException $e) {
                $this->assertSame('invalid_request', $e->error);
            }
        }
    }
}
