<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Client;

use CakeDC\OAuth\Server\Client\ApplicationType;
use CakeDC\OAuth\Server\Client\RedirectUriMatcher;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class RedirectUriMatcherTest extends TestCase
{
    public function testExactMatch(): void
    {
        $registered = ['https://claude.ai/api/mcp/auth_callback'];

        $this->assertTrue(RedirectUriMatcher::matches('https://claude.ai/api/mcp/auth_callback', $registered));
        $this->assertFalse(RedirectUriMatcher::matches('https://claude.ai/api/mcp/auth_callback/', $registered));
        $this->assertFalse(RedirectUriMatcher::matches('https://claude.ai/api/mcp/auth_callback?x=1', $registered));
        $this->assertFalse(RedirectUriMatcher::matches('https://CLAUDE.ai/api/mcp/auth_callback', $registered));
        $this->assertFalse(RedirectUriMatcher::matches('https://claude.ai:8443/api/mcp/auth_callback', $registered));
    }

    public function testLoopbackIgnoresOnlyThePort(): void
    {
        $registered = ['http://127.0.0.1/callback', 'http://localhost/callback'];

        $this->assertTrue(RedirectUriMatcher::matches('http://127.0.0.1:54321/callback', $registered));
        $this->assertTrue(RedirectUriMatcher::matches('http://localhost:3000/callback', $registered));
        $this->assertFalse(RedirectUriMatcher::matches('http://localhost:3000/callback', ['http://127.0.0.1/callback']));
        $this->assertFalse(RedirectUriMatcher::matches('http://127.0.0.1:3000/callback/x', $registered));
        $this->assertFalse(RedirectUriMatcher::matches('http://127.0.0.1:3000/callback?x=1', $registered));
        $this->assertFalse(RedirectUriMatcher::matches('https://127.0.0.1:3000/callback', $registered));
        $this->assertFalse(RedirectUriMatcher::matches('http://127.0.0.1:3000/callback#f', $registered));
    }

    /**
     * @return array<string, array{string, \CakeDC\OAuth\Server\Client\ApplicationType, bool, string|null}>
     */
    public static function registrations(): array
    {
        return [
            'https web' => ['https://app.example.com/cb', ApplicationType::Web, false, null],
            'loopback http' => ['http://127.0.0.1/cb', ApplicationType::Native, false, null],
            'loopback http for web' => ['http://localhost:3000/cb', ApplicationType::Web, false, null],
            'remote http' => ['http://app.example.com/cb', ApplicationType::Web, true, 'http is only allowed'],
            'fragment' => ['https://app.example.com/cb#x', ApplicationType::Web, true, 'fragment'],
            'javascript' => ['javascript:alert(1)', ApplicationType::Native, true, 'must not use the "javascript"'],
            'data' => ['data:text/html,hi', ApplicationType::Native, true, 'must not use the "data"'],
            'private scheme native' => ['cursor://anysphere.cursor/oauth', ApplicationType::Native, true, null],
            'private scheme disabled' => [
                'cursor://anysphere.cursor/oauth',
                ApplicationType::Native,
                false,
                'not allowed',
            ],
            'private scheme web' => ['cursor://anysphere.cursor/oauth', ApplicationType::Web, true, 'web clients'],
            'relative' => ['/cb', ApplicationType::Web, true, 'absolute URI'],
            'spaces' => ['https://app.example.com/a b', ApplicationType::Web, true, 'spaces'],
            'trailing newline' => ["https://app.example.com/cb\n", ApplicationType::Web, true, 'control characters'],
            'too long' => ['https://app.example.com/' . str_repeat('a', 2000), ApplicationType::Web, true, '2000'],
        ];
    }

    #[DataProvider('registrations')]
    public function testRegistrationRules(
        string $uri,
        ApplicationType $type,
        bool $privateSchemes,
        ?string $error,
    ): void {
        $result = RedirectUriMatcher::registrationError($uri, $type, $privateSchemes);

        if ($error === null) {
            $this->assertNull($result);
        } else {
            $this->assertNotNull($result);
            $this->assertStringContainsString($error, $result);
        }
    }
}
