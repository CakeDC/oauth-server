<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Http;

use CakeDC\OAuth\Server\Http\Params;
use PHPUnit\Framework\TestCase;

class ParamsTest extends TestCase
{
    public function testParsesFormEncodingKeepingTheFirstValue(): void
    {
        [$values, $repeated] = Params::parse('a=1&b=two+words&c=%2Fpath&a=2&d&&e=x%3Dy&b=3');

        $this->assertSame(['a' => '1', 'b' => 'two words', 'c' => '/path', 'd' => '', 'e' => 'x=y'], $values);
        $this->assertSame(['a', 'b'], $repeated);
    }

    public function testEmpty(): void
    {
        $this->assertSame([[], []], Params::parse(''));
    }
}
