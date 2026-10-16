<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Grant;

use CakeDC\OAuth\Server\Event\ConsentGranted;
use CakeDC\OAuth\Server\Grant\ConsentService;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Storage\InMemory\InMemoryStorage;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\RecordingEventDispatcher;
use CakeDC\OAuth\Server\Testing\FrozenClock;
use PHPUnit\Framework\TestCase;

class ConsentServiceTest extends TestCase
{
    public function testRemembersAndExtendsConsent(): void
    {
        $storage = new InMemoryStorage();
        $events = new RecordingEventDispatcher();
        $service = new ConsentService($storage, new FrozenClock(), $events);
        $owner = new ResourceOwner('42', 'Ada');
        $client = Fixtures::client();
        $mcp = Fixtures::resources()->get(Fixtures::MCP);
        $api = Fixtures::resources()->get(Fixtures::API);
        $this->assertNotNull($mcp);
        $this->assertNotNull($api);

        $this->assertFalse($service->isGranted($owner, $client, $mcp, ['content:read']));
        $service->grant($owner, $client, $mcp, ['content:read']);
        $this->assertTrue($service->isGranted($owner, $client, $mcp, ['content:read']));
        $this->assertFalse($service->isGranted($owner, $client, $mcp, ['content:write']));
        $this->assertFalse($service->isGranted($owner, $client, $api, ['api']));
        $this->assertFalse($service->isGranted(new ResourceOwner('43', 'Grace'), $client, $mcp, ['content:read']));

        $consent = $service->grant($owner, $client, $mcp, ['content:write']);
        $this->assertSame(['content:read', 'content:write'], $consent->scopes);
        $this->assertCount(2, $events->ofType(ConsentGranted::class));

        $deduped = $service->grant($owner, $client, $mcp, ['content:read', 'content:read']);
        $this->assertSame(['content:read', 'content:write'], $deduped->scopes);

        $service->forget('42', $client->id, Fixtures::MCP);
        $this->assertFalse($service->isGranted($owner, $client, $mcp, ['content:read']));
    }
}
