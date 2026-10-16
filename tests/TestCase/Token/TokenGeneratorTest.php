<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Token;

use CakeDC\OAuth\Server\Token\TokenGenerator;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

class TokenGeneratorTest extends TestCase
{
    public function testPrefixesEachKindOfSecret(): void
    {
        $generator = new TokenGenerator('kvg');

        $this->assertMatchesRegularExpression('/^kvg_at_[A-Za-z0-9_-]{43}$/', $generator->accessToken());
        $this->assertMatchesRegularExpression('/^kvg_rt_[A-Za-z0-9_-]{43}$/', $generator->refreshToken());
        $this->assertMatchesRegularExpression('/^kvg_pat_[A-Za-z0-9_-]{43}$/', $generator->personalToken());
        $this->assertMatchesRegularExpression('/^kvg_ac_[A-Za-z0-9_-]{43}$/', $generator->authorizationCode());
        $this->assertMatchesRegularExpression('/^kvg_cs_[A-Za-z0-9_-]{43}$/', $generator->clientSecret());
        $this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $generator->clientId());
        $this->assertNotSame($generator->accessToken(), $generator->accessToken());
    }

    public function testHashIsSha256(): void
    {
        $this->assertSame(hash('sha256', 'abc'), TokenGenerator::hash('abc'));
    }

    public function testRejectsAnInvalidPrefix(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new TokenGenerator('Bad_Prefix');
    }

    public function testRejectsAPrefixWithATrailingNewline(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new TokenGenerator("kvg\n");
    }
}
