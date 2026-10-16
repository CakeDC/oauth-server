<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Resource;

use CakeDC\OAuth\Server\Resource\ProtectedResource;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

class ProtectedResourceTest extends TestCase
{
    private function resource(): ProtectedResource
    {
        return ProtectedResource::fromArray('https://example.com/mcp', [
            'name' => 'Example',
            'scopes' => [
                'content:read' => 'Read content',
                'content:write' => 'Edit content',
                'content:publish' => 'Publish content',
                'media:write' => 'Upload images',
            ],
            'implies' => [
                'content:publish' => ['content:write'],
                'content:write' => ['content:read'],
            ],
            'defaultScopes' => ['content:read'],
        ]);
    }

    public function testExposesItsSettings(): void
    {
        $resource = $this->resource();

        $this->assertSame('https://example.com/mcp', $resource->identifier);
        $this->assertSame('Example', $resource->name);
        $this->assertSame(
            ['content:read', 'content:write', 'content:publish', 'media:write'],
            $resource->scopeNames(),
        );
        $this->assertTrue($resource->hasScope('media:write'));
        $this->assertFalse($resource->hasScope('offline_access'));
        $this->assertSame(['content:read'], $resource->defaultScopes);
    }

    public function testExpandsImpliedScopesTransitively(): void
    {
        $resource = $this->resource();

        $this->assertSame(
            ['content:publish', 'content:write', 'content:read'],
            $resource->expand(['content:publish']),
        );
        $this->assertSame(['media:write'], $resource->expand(['media:write']));
        $this->assertSame([], $resource->expand([]));
    }

    public function testNameDefaultsToTheHost(): void
    {
        $resource = ProtectedResource::fromArray('https://api.example.com', ['scopes' => ['read' => 'Read']]);

        $this->assertSame('api.example.com', $resource->name);
    }

    public function testRequiresACanonicalIdentifier(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('use "https://example.com/mcp"');

        new ProtectedResource('https://Example.com/mcp/', 'X', ['read' => 'Read']);
    }

    public function testRejectsUnknownScopesInImpliesAndDefaults(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('"admin"');

        new ProtectedResource('https://example.com', 'X', ['read' => 'Read'], ['read' => ['admin']]);
    }

    public function testOfflineAccessIsNotAResourceScope(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new ProtectedResource('https://example.com', 'X', ['offline_access' => 'Stay signed in']);
    }

    public function testNeedsAtLeastOneScope(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new ProtectedResource('https://example.com', 'X', []);
    }
}
