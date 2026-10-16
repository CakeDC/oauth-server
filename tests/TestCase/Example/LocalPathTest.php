<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Example;

use CakeDC\OAuth\Server\Example\LocalPath;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 3) . '/examples/standalone/LocalPath.php';

class LocalPathTest extends TestCase
{
    /**
     * @return array<string, array{string, string}>
     */
    public static function paths(): array
    {
        return [
            'valid path' => ['/oauth/authorize?client_id=a&x=%2F', '/oauth/authorize?client_id=a&x=%2F'],
            'root' => ['/', '/'],
            'protocol relative' => ['//evil.com', '/'],
            'backslash start' => ['/\\evil.com', '/'],
            'absolute url' => ['https://evil.com', '/'],
            'tab inside' => ["/\t/evil.com", '/'],
            'newline at the end' => ["/ok\n", '/'],
            'backslash later' => ['/a\\b', '/'],
            'empty' => ['', '/'],
            'relative' => ['evil', '/'],
        ];
    }

    #[DataProvider('paths')]
    public function testOnlyPlainLocalPathsPass(string $input, string $expected): void
    {
        $this->assertSame($expected, LocalPath::orHome($input));
    }
}
