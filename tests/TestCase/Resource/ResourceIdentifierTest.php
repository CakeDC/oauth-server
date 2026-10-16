<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Resource;

use CakeDC\OAuth\Server\Resource\ResourceIdentifier;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class ResourceIdentifierTest extends TestCase
{
    /**
     * @return array<string, array{string, string}>
     */
    public static function spellings(): array
    {
        return [
            'already canonical' => ['https://example.com/mcp', 'https://example.com/mcp'],
            'uppercase scheme and host' => ['HTTPS://Example.COM/mcp', 'https://example.com/mcp'],
            'default port' => ['https://example.com:443/mcp', 'https://example.com/mcp'],
            'other port kept' => ['https://example.com:8443/mcp', 'https://example.com:8443/mcp'],
            'trailing slash' => ['https://example.com/mcp/', 'https://example.com/mcp'],
            'root' => ['https://example.com/', 'https://example.com'],
            'path case kept' => ['https://example.com/MCP', 'https://example.com/MCP'],
            'query kept' => ['https://example.com/api?v=2', 'https://example.com/api?v=2'],
            'http default port' => ['http://localhost:80/mcp', 'http://localhost/mcp'],
        ];
    }

    #[DataProvider('spellings')]
    public function testCanonicalizes(string $input, string $expected): void
    {
        $this->assertSame($expected, ResourceIdentifier::canonicalize($input));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalid(): array
    {
        return [
            'relative' => ['/mcp'],
            'fragment' => ['https://example.com/mcp#x'],
            'empty fragment' => ['https://example.com/mcp#'],
            'credentials' => ['https://user:pass@example.com/mcp'],
            'other scheme' => ['ftp://example.com/mcp'],
        ];
    }

    #[DataProvider('invalid')]
    public function testRejects(string $input): void
    {
        $this->expectException(InvalidArgumentException::class);

        ResourceIdentifier::canonicalize($input);
    }

    public function testOnlyLoopbackHostsMayUsePlainHttp(): void
    {
        ResourceIdentifier::assertSecure('https://example.com', 'issuer');
        ResourceIdentifier::assertSecure('http://127.0.0.1:8080', 'issuer');
        ResourceIdentifier::assertSecure('http://[::1]:8080', 'issuer');
        ResourceIdentifier::assertSecure('http://localhost', 'issuer');

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The issuer "http://example.com" must use https.');
        ResourceIdentifier::assertSecure('http://example.com', 'issuer');
    }
}
