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

    public function testMalformedPercentEncodingIsKeptLiterally(): void
    {
        $this->assertSame([['a' => '%zz', 'b%' => '1'], []], Params::parse('a=%zz&b%=1'));
    }

    public function testEmptyNames(): void
    {
        $this->assertSame([['' => 'x'], []], Params::parse('=x'));
    }

    public function testBracketedNamesAreLiteralAndRepeat(): void
    {
        $this->assertSame([['a[]' => '1'], ['a[]']], Params::parse('a[]=1&a[]=2'));
    }

    public function testPlusIsASpaceInValues(): void
    {
        $this->assertSame([['q' => 'a b+c'], []], Params::parse('q=a+b%2Bc'));
    }
}
