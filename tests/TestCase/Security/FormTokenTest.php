<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Security;

use CakeDC\OAuth\Server\Security\FormToken;
use CakeDC\OAuth\Server\Testing\FrozenClock;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

class FormTokenTest extends TestCase
{
    public function testBindsContextSubjectAndTime(): void
    {
        $clock = new FrozenClock();
        $tokens = new FormToken(str_repeat('k', 32), $clock, 600);
        $token = $tokens->issue('consent:abc', '42');

        $this->assertTrue($tokens->verify($token, 'consent:abc', '42'));
        $this->assertFalse($tokens->verify($token, 'consent:abd', '42'));
        $this->assertFalse($tokens->verify($token, 'consent:abc', '43'));
        $this->assertFalse((new FormToken(str_repeat('x', 32), $clock))->verify($token, 'consent:abc', '42'));
        $this->assertFalse($tokens->verify('garbage', 'consent:abc', '42'));

        $clock->advance(601);
        $this->assertFalse($tokens->verify($token, 'consent:abc', '42'));
    }

    public function testRejectsAValidTokenWithATrailingNewline(): void
    {
        $tokens = new FormToken(str_repeat('k', 32), new FrozenClock());
        $token = $tokens->issue('consent:abc', '42');

        $this->assertTrue($tokens->verify($token, 'consent:abc', '42'));
        $this->assertFalse($tokens->verify($token . "\n", 'consent:abc', '42'));
    }

    public function testNewlinesInContextAndSubjectCannotShiftTheBoundary(): void
    {
        $tokens = new FormToken(str_repeat('k', 32), new FrozenClock());
        $token = $tokens->issue('consent:a', "x\ny");

        $this->assertTrue($tokens->verify($token, 'consent:a', "x\ny"));
        $this->assertFalse($tokens->verify($token, "consent:a\nx", 'y'));
    }

    public function testValidBeforeTtlAndInvalidAtTtl(): void
    {
        $clock = new FrozenClock();
        $tokens = new FormToken(str_repeat('k', 32), $clock, 600);
        $token = $tokens->issue('c', 's');

        $clock->advance(599);
        $this->assertTrue($tokens->verify($token, 'c', 's'));
        $clock->advance(1);
        $this->assertFalse($tokens->verify($token, 'c', 's'));
    }

    public function testTamperedExpiryFails(): void
    {
        $tokens = new FormToken(str_repeat('k', 32), new FrozenClock());
        [$expires, $mac] = explode('.', $tokens->issue('c', 's'));

        $this->assertFalse($tokens->verify(((int)$expires + 1000) . '.' . $mac, 'c', 's'));
    }

    public function testRejectsLeadingZeroExpiry(): void
    {
        $tokens = new FormToken(str_repeat('k', 32), new FrozenClock());
        [$expires, $mac] = explode('.', $tokens->issue('c', 's'));

        $this->assertFalse($tokens->verify('0' . $expires . '.' . $mac, 'c', 's'));
    }

    public function testRejectsAShortSecret(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new FormToken(str_repeat('k', 31), new FrozenClock());
    }
}
