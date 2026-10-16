<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Token;

use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Token\Token;
use CakeDC\OAuth\Server\Token\TokenType;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

class TokenTest extends TestCase
{
    private function token(?string $expires, ?string $revoked = null): Token
    {
        return new Token(
            id: 'id',
            tokenHash: 'hash',
            type: TokenType::Access,
            familyId: 'family',
            clientInternalId: 'client',
            subject: '1',
            subjectType: SubjectType::User,
            resource: 'https://example.com/mcp',
            scopes: ['read'],
            createdAt: new DateTimeImmutable('2026-01-01 00:00:00'),
            expiresAt: $expires === null ? null : new DateTimeImmutable($expires),
            revokedAt: $revoked === null ? null : new DateTimeImmutable($revoked),
        );
    }

    public function testActiveUntilExpiryOrRevocation(): void
    {
        $now = new DateTimeImmutable('2026-01-01 00:30:00');

        $this->assertTrue($this->token('2026-01-01 01:00:00')->isActive($now));
        $this->assertFalse($this->token('2026-01-01 00:30:00')->isActive($now));
        $this->assertTrue($this->token('2026-01-01 00:30:00')->isExpired($now));
        $this->assertFalse($this->token('2026-01-01 01:00:00', '2026-01-01 00:10:00')->isActive($now));
        $this->assertTrue($this->token(null)->isActive($now));
    }
}
