<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Scope;

use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Scope\Scopes;
use PHPUnit\Framework\TestCase;

class ScopesTest extends TestCase
{
    public function testParsesSpaceDelimitedUniqueScopes(): void
    {
        $parsed = Scopes::parse(' content:read  offline_access content:read ');
        $this->assertSame(['content:read', 'offline_access'], $parsed);
        $this->assertSame([], Scopes::parse(null));
        $this->assertSame([], Scopes::parse('   '));
        $this->assertSame(['123'], Scopes::parse('123'));
    }

    public function testRejectsCharactersOutsideTheScopeTokenGrammar(): void
    {
        $this->expectException(OAuthException::class);
        $this->expectExceptionMessage("'a?b' is not a valid scope.");

        Scopes::parse('ok a"b');
    }

    public function testFormatsAndValidates(): void
    {
        $this->assertSame('a b', Scopes::format(['a', 'b']));
        $this->assertTrue(Scopes::isValid('files:write'));
        $this->assertFalse(Scopes::isValid(''));
        $this->assertFalse(Scopes::isValid("a\n"));
        $this->assertFalse(Scopes::isValid('back\\slash'));
    }
}
