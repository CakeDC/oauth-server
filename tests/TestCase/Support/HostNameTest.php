<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Support;

use CakeDC\OAuth\Server\Support\HostName;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class HostNameTest extends TestCase
{
    /**
     * @return array<string, array{string, bool}>
     */
    public static function hosts(): array
    {
        return [
            'plain' => ['client.example', true],
            'uppercase' => ['Client.Example', true],
            'subdomain with hyphen' => ['a-b.client.example', true],
            'ipv4' => ['93.184.216.34', true],
            'ipv6' => ['[2606:4700:4700::1111]', true],
            'bare ipv6' => ['::1', false],
            'bad bracketed' => ['[nope]', false],
            'empty' => ['', false],
            'single label' => ['localhost', false],
            'percent' => ['x%41.attacker.example', false],
            'decimal' => ['2130706433', false],
            'hex dotted' => ['0x7f.0.0.1', false],
            'octal dotted' => ['0177.0.0.1', false],
            'numeric tld' => ['client.123', false],
            'trailing dot' => ['client.example.', false],
            'leading hyphen' => ['-a.example', false],
            'trailing hyphen' => ['a-.example', false],
            'empty label' => ['a..example', false],
            'underscore' => ['a_b.example', false],
            'long label' => [str_repeat('a', 64) . '.example', false],
            'long host' => [str_repeat('a.', 130) . 'example', false],
            'newline' => ["client.example\n", false],
            'non-ascii' => ['cl\u{00ED}ent.example', false],
        ];
    }

    #[DataProvider('hosts')]
    public function testValidatesHosts(string $host, bool $valid): void
    {
        $this->assertSame($valid, HostName::isValid($host));
    }
}
