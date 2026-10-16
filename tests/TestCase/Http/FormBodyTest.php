<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Http;

use CakeDC\OAuth\Server\Http\FormBody;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

class FormBodyTest extends TestCase
{
    public function testReadsTheRawBodyAndDetectsRepeats(): void
    {
        $request = new ServerRequest(
            'POST',
            '/token',
            ['Content-Type' => 'application/x-www-form-urlencoded'],
            'a=1&b=2&a=3',
        );
        $request->getBody()->getContents();

        $this->assertSame([['a' => '1', 'b' => '2'], ['a']], FormBody::read($request));
        $this->assertTrue(FormBody::isForm($request));
    }

    public function testFallsBackToTheParsedBodyWhenTheStreamIsEmpty(): void
    {
        $request = (new ServerRequest(
            'POST',
            '/token',
            ['Content-Type' => 'application/x-www-form-urlencoded; charset=UTF-8'],
        ))->withParsedBody(['grant_type' => 'refresh_token', 'nested' => ['x' => 'y']]);

        $this->assertSame([['grant_type' => 'refresh_token'], []], FormBody::read($request));
        $this->assertTrue(FormBody::isForm($request));
        $json = new ServerRequest('POST', '/token', ['Content-Type' => 'application/json']);
        $this->assertFalse(FormBody::isForm($json));
    }

    public function testMediaTypeMustMatchExactly(): void
    {
        $make = fn(string $type) => new ServerRequest('POST', '/t', ['Content-Type' => $type]);

        $this->assertFalse(FormBody::isForm($make('application/x-www-form-urlencodedX')));
        $this->assertTrue(FormBody::isForm($make('application/x-www-form-urlencoded; charset=UTF-8')));
        $this->assertTrue(FormBody::isForm($make(' Application/X-WWW-Form-Urlencoded ')));
    }
}
