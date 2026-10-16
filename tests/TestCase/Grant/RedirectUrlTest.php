<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Grant;

use CakeDC\OAuth\Server\Grant\RedirectUrl;
use PHPUnit\Framework\TestCase;

class RedirectUrlTest extends TestCase
{
    public function testAppendsParameters(): void
    {
        $this->assertSame(
            'https://app.example.com/cb?code=a%20b&iss=https%3A%2F%2Fexample.com',
            RedirectUrl::build('https://app.example.com/cb', ['code' => 'a b', 'state' => null, 'iss' => 'https://example.com']),
        );
        $this->assertSame(
            'https://app.example.com/cb?x=1&code=c',
            RedirectUrl::build('https://app.example.com/cb?x=1', ['code' => 'c']),
        );
    }
}
