<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\View\Html;

use CakeDC\OAuth\Server\Client\ClientType;
use CakeDC\OAuth\Server\Connections\Connection;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\View\ConnectionsView;
use CakeDC\OAuth\Server\View\Html\HtmlConnectionsRenderer;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

class HtmlConnectionsRendererTest extends TestCase
{
    public function testRendersConnectionsTokensAndTheCreateForm(): void
    {
        $connection = new Connection(
            'family-1',
            Fixtures::client(['name' => 'Claude <AI>']),
            Fixtures::MCP,
            ['content:read'],
            new DateTimeImmutable('2026-01-02 10:00:00'),
            null,
        );
        $html = (new HtmlConnectionsRenderer())->render(new ConnectionsView(
            new ResourceOwner('42', 'Ada'),
            [$connection],
            [],
            [Fixtures::MCP => ['name' => 'Example MCP', 'scopes' => ['content:read' => 'Read your posts']]],
            [Fixtures::MCP => 'Example MCP'],
            '/oauth/connections',
            'form-token',
            90,
            true,
            'oauth_pat_secret',
        ));

        $this->assertStringContainsString('Claude &lt;AI&gt;', $html);
        $this->assertStringContainsString('Example MCP', $html);
        $this->assertStringContainsString('2026-01-02 10:00 UTC', $html);
        $this->assertStringContainsString('Never', $html);
        $this->assertStringContainsString('<input type="hidden" name="family_id" value="family-1">', $html);
        $this->assertStringContainsString('<input type="hidden" name="form_token" value="form-token">', $html);
        $this->assertStringContainsString('name="scope:content:read" value="1"', $html);
        $this->assertStringContainsString('max="90"', $html);
        $this->assertStringContainsString('<code>oauth_pat_secret</code>', $html);
        $this->assertStringContainsString('You have no personal access tokens.', $html);
    }

    public function testHidesPersonalTokensWhenDisabled(): void
    {
        $html = (new HtmlConnectionsRenderer())->render(new ConnectionsView(
            new ResourceOwner('42', 'Ada'),
            [],
            [],
            [],
            [],
            '/oauth/connections',
            't',
            90,
            false,
        ));

        $this->assertStringContainsString('No application is connected.', $html);
        $this->assertStringNotContainsString('Personal access tokens', $html);
    }

    public function testNamesMetadataClientsByHostAndMarksRegisteredOnesUnverified(): void
    {
        $cimd = Fixtures::client([
            'clientId' => 'https://app.example.org/client.json',
            'name' => 'Trusted Name',
            'type' => ClientType::MetadataDocument,
        ]);
        $dynamic = Fixtures::client(['name' => 'Self Registered', 'type' => ClientType::Dynamic]);
        $at = new DateTimeImmutable('2026-01-02 10:00:00');
        $html = (new HtmlConnectionsRenderer())->render(new ConnectionsView(
            new ResourceOwner('42', 'Ada'),
            [
                new Connection('f1', $cimd, Fixtures::MCP, ['content:read'], $at, null),
                new Connection('f2', $dynamic, Fixtures::MCP, ['content:read'], $at, null),
            ],
            [],
            [],
            [],
            '/oauth/connections',
            't',
            90,
            false,
        ));

        $this->assertStringContainsString('app.example.org', $html);
        $this->assertStringNotContainsString('Trusted Name', $html);
        $this->assertStringContainsString('Self Registered', $html);
        $this->assertSame(1, substr_count($html, 'Unverified: this application registered itself.'));
    }
}
