<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Resource;

use CakeDC\OAuth\Server\Resource\ResourceRegistry;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

class ResourceRegistryTest extends TestCase
{
    private function registry(?string $default = null): ResourceRegistry
    {
        return ResourceRegistry::fromArray([
            'https://example.com/mcp/' => [
                'name' => 'MCP',
                'scopes' => ['content:read' => 'Read', 'content:write' => 'Write'],
            ],
            'https://example.com/api' => ['name' => 'API', 'scopes' => ['api' => 'Use the API']],
        ], $default);
    }

    public function testLooksUpAnySpelling(): void
    {
        $registry = $this->registry();

        $this->assertSame('MCP', $registry->get('HTTPS://Example.com:443/mcp/')?->name);
        $this->assertSame('MCP', $registry->get('https://example.com/mcp')?->name);
        $this->assertNull($registry->get('https://example.com/other'));
        $this->assertNull($registry->get('not a url'));
    }

    public function testTheFirstResourceIsTheDefaultUnlessConfigured(): void
    {
        $this->assertSame('https://example.com/mcp', $this->registry()->defaultResource()->identifier);
        $this->assertSame(
            'https://example.com/api',
            $this->registry('https://example.com/api/')->defaultResource()->identifier,
        );
    }

    public function testListsResourcesAndScopes(): void
    {
        $registry = $this->registry();

        $this->assertCount(2, $registry->all());
        $this->assertSame(['content:read', 'content:write', 'api'], $registry->allScopeNames());
    }

    public function testRejectsAnUnknownDefault(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->registry('https://example.com/nope');
    }

    public function testRejectsDuplicates(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('declared twice');

        ResourceRegistry::fromArray([
            'https://example.com/mcp' => ['scopes' => ['a' => 'A']],
            'https://example.com/mcp/' => ['scopes' => ['b' => 'B']],
        ]);
    }

    public function testNeedsAResource(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new ResourceRegistry([]);
    }
}
