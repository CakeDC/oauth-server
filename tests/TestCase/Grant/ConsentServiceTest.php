<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Grant;

use CakeDC\OAuth\Server\Client\ClientAuthMethod;
use CakeDC\OAuth\Server\Event\ConsentGranted;
use CakeDC\OAuth\Server\Grant\ConsentService;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Storage\InMemory\InMemoryStorage;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\RecordingEventDispatcher;
use CakeDC\OAuth\Server\Testing\FrozenClock;
use PHPUnit\Framework\Attributes\DataProvider;
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

    public function testHasConsentedLooksAtEveryResourceOfThatClientOnly(): void
    {
        $service = new ConsentService(new InMemoryStorage(), new FrozenClock(), new RecordingEventDispatcher());
        $owner = new ResourceOwner('42', 'Ada');
        $client = Fixtures::client();
        $other = Fixtures::client();
        $api = Fixtures::resources()->get(Fixtures::API);
        $this->assertNotNull($api);

        $this->assertFalse($service->hasConsented($owner, $client));
        $service->grant($owner, $client, $api, ['api']);

        $this->assertTrue($service->hasConsented($owner, $client));
        $this->assertFalse($service->hasConsented($owner, $other));
        $this->assertFalse($service->hasConsented(new ResourceOwner('43', 'Grace'), $client));
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function redirects(): array
    {
        return [
            'https host' => ['https://app.example.com/cb', true],
            'https IP' => ['https://203.0.113.5/cb', true],
            'loopback http' => ['http://127.0.0.1:51000/callback', false],
            'localhost http' => ['http://localhost:3000/callback', false],
            'https localhost' => ['https://localhost:8443/cb', false],
            'https .localhost name' => ['https://app.localhost/cb', false],
            'https loopback range' => ['https://127.0.0.5/cb', false],
            'https IPv6 loopback' => ['https://[::1]:8443/cb', false],
            'https IPv6 loopback, long form' => ['https://[0:0:0:0:0:0:0:1]/cb', false],
            'https IPv4-mapped loopback' => ['https://[::ffff:127.0.0.1]/cb', false],
            'https unspecified IPv4' => ['https://0.0.0.0/cb', false],
            'https unspecified IPv6' => ['https://[::]/cb', false],
            'https this network' => ['https://0.1.2.3/cb', false],
            'https IPv4-mapped unspecified' => ['https://[::ffff:0.0.0.0]/cb', false],
            'private scheme' => ['com.example.app:/cb', false],
            'private scheme with authority' => ['com.example.app://cb', false],
        ];
    }

    #[DataProvider('redirects')]
    public function testIdentityIsAssuredOnlyForRemoteHttpsOrASecret(string $redirectUri, bool $assured): void
    {
        $service = new ConsentService(new InMemoryStorage(), new FrozenClock(), new RecordingEventDispatcher());

        $this->assertSame($assured, $service->identityIsAssured(Fixtures::client(), $redirectUri));
        $confidential = Fixtures::client(['authMethod' => ClientAuthMethod::SecretBasic]);
        $this->assertTrue($service->identityIsAssured($confidential, $redirectUri));
    }
}
