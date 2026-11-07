<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Token;

use CakeDC\OAuth\Server\Token\RotationSeal;
use PHPUnit\Framework\TestCase;

class RotationSealTest extends TestCase
{
    public function testOpensWithTheRotatedTokenAndTheSecret(): void
    {
        $seal = new RotationSeal(str_repeat('s', 32));

        $sealed = $seal->seal('oauth_rt_rotated', 'oauth_at_new', 'oauth_rt_new');

        $this->assertSame(['oauth_at_new', 'oauth_rt_new'], $seal->open('oauth_rt_rotated', $sealed));
    }

    public function testHidesTheValues(): void
    {
        $sealed = (new RotationSeal(str_repeat('s', 32)))->seal('oauth_rt_rotated', 'oauth_at_new', 'oauth_rt_new');

        $bytes = (string)base64_decode($sealed, true);
        $this->assertStringNotContainsString('oauth_at_new', $bytes);
        $this->assertStringNotContainsString('oauth_rt_new', $bytes);
    }

    public function testEverySealIsDifferent(): void
    {
        $seal = new RotationSeal(str_repeat('s', 32));

        $this->assertNotSame(
            $seal->seal('oauth_rt_rotated', 'oauth_at_new', 'oauth_rt_new'),
            $seal->seal('oauth_rt_rotated', 'oauth_at_new', 'oauth_rt_new'),
        );
    }

    public function testAnotherTokenOrSecretDoesNotYieldTheValues(): void
    {
        $sealed = (new RotationSeal(str_repeat('s', 32)))->seal('oauth_rt_rotated', 'oauth_at_new', 'oauth_rt_new');

        $this->assertNotSame(
            ['oauth_at_new', 'oauth_rt_new'],
            (new RotationSeal(str_repeat('s', 32)))->open('oauth_rt_other', $sealed),
        );
        $this->assertNotSame(
            ['oauth_at_new', 'oauth_rt_new'],
            (new RotationSeal(str_repeat('t', 32)))->open('oauth_rt_rotated', $sealed),
        );
    }

    public function testMalformedSealsAreNull(): void
    {
        $seal = new RotationSeal(str_repeat('s', 32));

        $this->assertNull($seal->open('oauth_rt_rotated', 'not base64 !'));
        $this->assertNull($seal->open('oauth_rt_rotated', base64_encode('short')));
        $this->assertNull($seal->open('oauth_rt_rotated', ''));
    }
}
