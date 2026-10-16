<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Security;

use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9700, "307 Redirect": after the consent POST the browser is sent back with 303, so it never
 * re-posts the form (with the person's data) to the client.
 */
class RedirectStatusTest extends TestCase
{
    public function testConsentDecisionsUse303(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $harness->signIn();
        foreach (['approve', 'deny'] as $decision) {
            $url = $harness->authorizeUrl($client, ['scope' => 'content:publish']);
            $page = $harness->server->authorizeHandler()->handle($harness->request('GET', $url));
            $fields = ServerHarness::formFields((string)$page->getBody()) + ['decision' => $decision];
            $this->assertArrayHasKey('consent_token', $fields, 'No consent form for ' . $decision);

            $response = $harness->server->authorizeHandler()->handle(
                $harness->form('https://example.com/oauth/authorize', $fields),
            );

            $this->assertSame(303, $response->getStatusCode(), $decision);
            $harness->storage->deleteConsent('42', $client->id, 'https://example.com/mcp');
        }
    }
}
