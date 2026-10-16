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

    public function testLoopbackRejectsControlCharactersInTheRequestedUri(): void
    {
        $registered = ['http://127.0.0.1/auth_callback'];

        foreach (["\n", "\r", "\0", '\\'] as $char) {
            $this->assertFalse(RedirectUriMatcher::matches("http://127.0.0.1:3000/auth{$char}callback", $registered));
        }
        $this->assertFalse(RedirectUriMatcher::matches("http://127.0.0.1:3000/auth_callback\n", $registered));
        $this->assertFalse(RedirectUriMatcher::matches('http://u@127.0.0.1:3000/auth_callback', $registered));
        $this->assertTrue(RedirectUriMatcher::matches('http://127.0.0.1:3000/auth_callback', $registered));
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
            'private scheme native' => ['com.example.app:/oauth', ApplicationType::Native, true, null],
            'private scheme with authority' => ['com.example.app://oauth/cb', ApplicationType::Native, true, null],
            'private scheme disabled' => [
                'com.example.app:/oauth',
                ApplicationType::Native,
                false,
                'not allowed',
            ],
            // A host that enables private schemes accepts any scheme that is not a dangerous one.
            'private scheme without a dot' => ['myapp:/cb', ApplicationType::Native, true, null],
            'cursor scheme' => ['cursor://anysphere.cursor/oauth', ApplicationType::Native, true, null],
            'dangerous scheme even when enabled' => [
                'blob:https://app.example.com/x',
                ApplicationType::Native,
                true,
                'must not use the "blob"',
            ],
            'private scheme web' => ['com.example.app:/oauth', ApplicationType::Web, true, 'web clients'],
            'percent-encoded host' => [
                'https://claude.ai%2eevil.example/cb',
                ApplicationType::Web,
                true,
                'plain host name',
            ],
            'https localhost' => ['https://localhost:8443/cb', ApplicationType::Web, false, null],
            'encoded localhost subdomain' => [
                'https://x%41.localhost/cb',
                ApplicationType::Web,
                true,
                'plain host name',
            ],
            'decimal host' => ['https://2130706433/cb', ApplicationType::Web, true, 'plain host name'],
            'relative' => ['/cb', ApplicationType::Web, true, 'absolute URI'],
            'spaces' => ['https://app.example.com/a b', ApplicationType::Web, true, 'spaces'],
            'trailing newline' => ["https://app.example.com/cb\n", ApplicationType::Web, true, 'control characters'],
            'backslash' => [
                'https://evil.example\\@claude.ai/api/mcp/auth_callback',
                ApplicationType::Web,
                true,
                'RFC 3986',
            ],
            'homograph' => ["https://cl\u{0430}ude.ai/cb", ApplicationType::Web, true, 'RFC 3986'],
            'userinfo' => ['https://claude.ai@evil.example/cb', ApplicationType::Web, true, 'user information'],
            'userinfo with password' => ['https://a:b@evil.example/cb', ApplicationType::Web, true, 'user information'],
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

    /**
     * @return array<string, array{string}>
     */
    public static function notLoopbackLiterals(): array
    {
        return [
            'loopback range' => ['http://127.0.0.5/cb'],
            'unspecified' => ['http://0.0.0.0/cb'],
            '.localhost name' => ['http://app.localhost/cb'],
            'unspecified IPv6' => ['http://[::]/cb'],
        ];
    }

    #[DataProvider('notLoopbackLiterals')]
    public function testPlainHttpIsOnlyForTheLoopbackLiteralsOfRfc8252(string $uri): void
    {
        $this->assertNotNull(RedirectUriMatcher::registrationError($uri, ApplicationType::Native, true));
        $this->assertFalse(RedirectUriMatcher::matches($uri, ['http://127.0.0.1/cb']));
        $this->assertFalse(RedirectUriMatcher::matches('http://127.0.0.1/cb', [$uri]));
    }
}
