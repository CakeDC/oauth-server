<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Support;

use CakeDC\OAuth\Server\Support\Base64Url;
use CakeDC\OAuth\Server\Support\Time;
use CakeDC\OAuth\Server\Support\Uuid;
use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\TestCase;

class SupportTest extends TestCase
{
    public function testBase64UrlHasNoPaddingOrUnsafeCharacters(): void
    {
        $this->assertSame('-_8', Base64Url::encode("\xfb\xff"));
        $this->assertSame('YQ', Base64Url::encode('a'));
    }

    public function testUuidIsVersion4(): void
    {
        $uuid = Uuid::v4();

        $this->assertMatchesRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/',
            $uuid,
        );
        $this->assertNotSame($uuid, Uuid::v4());
    }

    public function testTimeHelpersWorkInUtc(): void
    {
        $time = new DateTimeImmutable('2026-01-01 23:59:30', new DateTimeZone('Europe/Madrid'));

        $this->assertSame('2026-01-01 22:59:30', Time::format($time));
        $this->assertSame('2026-01-01 23:00:00', Time::format(Time::plus($time, 30)));
        $this->assertSame('2026-01-01 22:59:30', Time::format(Time::parse('2026-01-01 22:59:30')));
        $this->assertSame('UTC', Time::parse('2026-01-01 22:59:30')->getTimezone()->getName());
    }
}
