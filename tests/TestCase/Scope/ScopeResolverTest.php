<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Scope;

use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Resource\ProtectedResource;
use CakeDC\OAuth\Server\Scope\ScopeResolver;
use PHPUnit\Framework\TestCase;

class ScopeResolverTest extends TestCase
{
    private ProtectedResource $resource;

    private ScopeResolver $resolver;

    protected function setUp(): void
    {
        $this->resource = new ProtectedResource(
            'https://example.com/mcp',
            'Example',
            ['read' => 'Read', 'write' => 'Write', 'publish' => 'Publish', 'media' => 'Media'],
            ['publish' => ['write'], 'write' => ['read']],
            ['read'],
        );
        $this->resolver = new ScopeResolver();
    }

    public function testNoRequestedScopeMeansTheDefaults(): void
    {
        $this->assertSame(['read'], $this->resolver->resolve($this->resource, [], null, null));
    }

    public function testKeepsWhatClientAndOwnerMayHold(): void
    {
        $this->assertSame(
            ['write', 'media'],
            $this->resolver->resolve($this->resource, ['write', 'media', 'publish'], null, ['write', 'media']),
        );
        $this->assertSame(['read'], $this->resolver->resolve($this->resource, ['read', 'media'], ['publish'], null));
        $this->assertSame([], $this->resolver->resolve($this->resource, ['media'], ['read'], null));
    }

    public function testAnOwnerWithAHigherScopeHoldsTheImpliedOnes(): void
    {
        $this->assertSame(
            ['read', 'write'],
            $this->resolver->resolve($this->resource, ['read', 'write'], null, ['publish']),
        );
    }

    public function testUnknownScopesAreRejected(): void
    {
        $this->expectException(OAuthException::class);
        $this->expectExceptionMessage("'admin'");

        $this->resolver->resolve($this->resource, ['read', 'admin'], null, null);
    }

    public function testEffectiveScopesFollowTheOwnerNow(): void
    {
        $this->assertSame(
            ['publish', 'write', 'read'],
            $this->resolver->effective($this->resource, ['publish'], null, null),
        );
        $this->assertSame(['write', 'read'], $this->resolver->effective($this->resource, ['publish'], null, ['write']));
        $this->assertSame(['read'], $this->resolver->effective($this->resource, ['publish', 'media'], ['read'], null));
    }

    public function testEffectiveDropsScopesTheResourceNoLongerDeclares(): void
    {
        $resource = new ProtectedResource('https://example.com/mcp', 'Example', ['read' => 'Read']);

        $this->assertSame(['read'], $this->resolver->effective($resource, ['read', 'legacy'], null, null));
    }

    public function testNarrowingOnRefresh(): void
    {
        $this->assertSame(['write', 'media'], $this->resolver->narrow($this->resource, ['write', 'media'], []));
        $this->assertSame(['read'], $this->resolver->narrow($this->resource, ['write'], ['read']));

        $this->expectException(OAuthException::class);
        $this->resolver->narrow($this->resource, ['write'], ['publish']);
    }

    /**
     * What a refresh issues today, which the introspection of a refresh token reports too.
     */
    public function testRefreshedScopes(): void
    {
        $this->assertSame(['write', 'media'], $this->resolver->refreshed($this->resource, ['write', 'media'], [], null, null));
        $this->assertSame(['read'], $this->resolver->refreshed($this->resource, ['write', 'media'], ['read'], null, null));
        $this->assertSame(['write'], $this->resolver->refreshed($this->resource, ['write', 'gone'], [], ['publish'], null));
        $this->assertSame(['read'], $this->resolver->refreshed($this->resource, ['write'], [], null, ['read', 'media']));
        // A narrowed client narrows the grant the way a demoted owner does, to the minimal set.
        $this->assertSame(['read'], $this->resolver->refreshed($this->resource, ['write'], [], ['read'], null));
        $this->assertSame(['write'], $this->resolver->refreshed($this->resource, ['publish'], [], ['write', 'read'], null));
        $this->assertSame(['read'], $this->resolver->refreshed($this->resource, ['publish', 'media'], [], ['read'], ['write']));

        $errors = [];
        foreach ([[['media'], null], [null, ['media']]] as [$client, $owner]) {
            try {
                $this->resolver->refreshed($this->resource, ['write'], [], $client, $owner);
            } catch (OAuthException $e) {
                $errors[] = $e->error;
            }
        }
        $this->assertSame(['invalid_scope', 'invalid_grant'], $errors);
    }
}
