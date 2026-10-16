<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Grant;

use CakeDC\OAuth\Server\Grant\Consent;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

class ConsentTest extends TestCase
{
    public function testCoversASubsetOfItsScopes(): void
    {
        $at = new DateTimeImmutable('2026-01-01 00:00:00');
        $consent = new Consent('id', '1', 'client', 'https://example.com/mcp', ['read', 'write'], $at, $at);

        $this->assertTrue($consent->covers(['read']));
        $this->assertTrue($consent->covers(['write', 'read']));
        $this->assertTrue($consent->covers([]));
        $this->assertFalse($consent->covers(['read', 'publish']));
    }
}
