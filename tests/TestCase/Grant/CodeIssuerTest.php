<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Grant;

use CakeDC\OAuth\Server\Grant\AuthorizationRequest;
use CakeDC\OAuth\Server\Grant\CodeIssuer;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Storage\InMemory\InMemoryStorage;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Testing\FrozenClock;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use PHPUnit\Framework\TestCase;

class CodeIssuerTest extends TestCase
{
    public function testStoresAHashedShortLivedCode(): void
    {
        $storage = new InMemoryStorage();
        $clock = new FrozenClock();
        $client = Fixtures::client();
        $resource = Fixtures::resources()->defaultResource();
        $request = new AuthorizationRequest(
            $client,
            'https://app.example.com/cb',
            'state',
            $resource,
            ['content:write'],
            true,
            str_repeat('c', 43),
            [],
        );

        $code = (new CodeIssuer($storage, new TokenGenerator(), $clock, 60))
            ->issue($request, new ResourceOwner('42', 'Ada'), ['content:write']);

        $this->assertStringStartsWith('oauth_ac_', $code);
        $stored = $storage->findCodeByHash(TokenGenerator::hash($code));
        $this->assertNotNull($stored);
        $this->assertSame($client->id, $stored->clientInternalId);
        $this->assertSame('42', $stored->subject);
        $this->assertSame(['content:write', 'offline_access'], $stored->scopes);
        $this->assertSame(Fixtures::MCP, $stored->resource);
        $this->assertSame(60, $stored->expiresAt->getTimestamp() - $clock->now()->getTimestamp());
        $this->assertNull($stored->usedAt);
    }

    public function testScopesAreDeduplicated(): void
    {
        $storage = new InMemoryStorage();
        $client = Fixtures::client();
        $request = new AuthorizationRequest(
            $client,
            'https://app.example.com/cb',
            null,
            Fixtures::resources()->defaultResource(),
            [],
            true,
            str_repeat('c', 43),
            [],
        );
        $code = (new CodeIssuer($storage, new TokenGenerator(), new FrozenClock()))
            ->issue($request, new ResourceOwner('42', 'Ada'), ['a', 'offline_access', 'a']);

        $this->assertSame(['a', 'offline_access'], $storage->findCodeByHash(TokenGenerator::hash($code))?->scopes);
    }
}
