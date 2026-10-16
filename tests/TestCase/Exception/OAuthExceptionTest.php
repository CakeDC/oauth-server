<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Exception;

use CakeDC\OAuth\Server\Exception\OAuthException;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class OAuthExceptionTest extends TestCase
{
    public function testCarriesTheRfc6749Body(): void
    {
        $e = OAuthException::invalidGrant('The code expired.');

        $this->assertSame('invalid_grant', $e->error);
        $this->assertSame(400, $e->status);
        $this->assertSame(['error' => 'invalid_grant', 'error_description' => 'The code expired.'], $e->toArray());
    }

    public function testInvalidClientWithBasicAuthenticationChallenges(): void
    {
        $this->assertSame([], OAuthException::invalidClient('x')->headers);
        $e = OAuthException::invalidClient('Bad secret.', true);

        $this->assertSame(401, $e->status);
        $this->assertSame(['WWW-Authenticate' => 'Basic realm="oauth"'], $e->headers);
    }

    public function testStatusCodes(): void
    {
        $this->assertSame(401, OAuthException::invalidToken('x')->status);
        $this->assertSame(500, OAuthException::serverError()->status);
        $this->assertSame('invalid_target', OAuthException::invalidTarget('x')->error);
        $this->assertSame('invalid_redirect_uri', OAuthException::invalidRedirectUri('x')->error);
        $this->assertSame('invalid_client_metadata', OAuthException::invalidClientMetadata('x')->error);
    }

    public function testRateLimitedTellsWhenToRetry(): void
    {
        $e = OAuthException::rateLimited(42);

        $this->assertSame(429, $e->status);
        $this->assertSame('temporarily_unavailable', $e->error);
        $this->assertSame(['Retry-After' => '42'], $e->headers);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function descriptionsOutsideTheRfcSet(): array
    {
        return [
            'double quote' => ['"code" is missing.'],
            'backslash' => ['a \\ b'],
            'line feed' => ["two\nlines"],
            'tab' => ["a\tb"],
            'delete' => ["a\x7Fb"],
            'non-ascii' => ['caf' . "\u{00E9}"],
            'invalid utf-8' => ["\xC3"],
        ];
    }

    /**
     * RFC 6749 sections 4.1.2.1 and 5.2: error_description is %x20-21 / %x23-5B / %x5D-7E.
     */
    #[DataProvider('descriptionsOutsideTheRfcSet')]
    public function testRefusesADescriptionOutsideTheRfcCharacterSet(string $description): void
    {
        $this->assertFalse(OAuthException::isValidDescription($description));
        $this->expectException(InvalidArgumentException::class);

        new OAuthException('invalid_request', $description);
    }

    public function testAcceptsEveryCharacterOfTheRfcSet(): void
    {
        $all = '';
        foreach ([...range(0x20, 0x21), ...range(0x23, 0x5B), ...range(0x5D, 0x7E)] as $byte) {
            $all .= chr($byte);
        }

        $this->assertTrue(OAuthException::isValidDescription($all));
        $this->assertSame($all, OAuthException::invalidRequest($all)->getMessage());
        $this->assertTrue(OAuthException::isValidDescription(''));
    }

    public function testPrintableMakesAnyRequestValueFitADescription(): void
    {
        $hostile = "a\"b\\c\nd\u{00E9}\xC3" . str_repeat('x', 200);
        $printable = OAuthException::printable($hostile);

        $this->assertTrue(OAuthException::isValidDescription($printable));
        $this->assertStringStartsWith('a?b?c?d?', $printable);
        $this->assertLessThanOrEqual(67, strlen($printable));
        $this->assertStringEndsWith('...', $printable);
        $this->assertSame('content:read', OAuthException::printable('content:read'));
    }
}
