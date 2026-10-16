<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Grant;

use CakeDC\OAuth\Server\Grant\Pkce;
use PHPUnit\Framework\TestCase;

class PkceTest extends TestCase
{
    public function testVerifiesTheRfc7636Example(): void
    {
        $verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
        $challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

        $this->assertSame($challenge, Pkce::challengeFor($verifier));
        $this->assertTrue(Pkce::verify($verifier, $challenge));
        $this->assertFalse(Pkce::verify($verifier . 'x', $challenge));
    }

    public function testValidatesFormats(): void
    {
        $this->assertTrue(Pkce::isValidChallenge('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'));
        $this->assertFalse(Pkce::isValidChallenge('short'));
        $this->assertFalse(Pkce::isValidChallenge('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw+cM'));
        $this->assertTrue(Pkce::isValidVerifier(str_repeat('a', 43)));
        $this->assertTrue(Pkce::isValidVerifier(str_repeat('a', 128)));
        $this->assertFalse(Pkce::isValidVerifier(str_repeat('a', 42)));
        $this->assertFalse(Pkce::isValidVerifier(str_repeat('a', 129)));
        $this->assertFalse(Pkce::verify(str_repeat('!', 43), Pkce::challengeFor(str_repeat('!', 43))));
    }

    public function testRejectsAChallengeWithATrailingNewline(): void
    {
        $this->assertFalse(Pkce::isValidChallenge("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c\n"));
    }

    public function testRejectsAVerifierWithATrailingNewline(): void
    {
        $this->assertFalse(Pkce::isValidVerifier(str_repeat('a', 43) . "\n"));
    }
}
