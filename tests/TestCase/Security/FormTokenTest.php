<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Security;

use CakeDC\OAuth\Server\Security\FormToken;
use CakeDC\OAuth\Server\Testing\FrozenClock;
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
}
