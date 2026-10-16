<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Exception;

use CakeDC\OAuth\Server\Exception\OAuthException;
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
}
