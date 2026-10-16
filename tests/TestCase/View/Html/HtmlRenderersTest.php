<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\View\Html;

use CakeDC\OAuth\Server\Client\ClientType;
use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\View\ConsentView;
use CakeDC\OAuth\Server\View\Html\HtmlConsentRenderer;
use CakeDC\OAuth\Server\View\Html\HtmlErrorPageRenderer;
use CakeDC\OAuth\Server\View\Messages;
use PHPUnit\Framework\TestCase;

class HtmlRenderersTest extends TestCase
{
    private function view(ClientType $type = ClientType::Dynamic, array $redirects = ['https://app.example.com/cb']): ConsentView
    {
        return new ConsentView(
            Fixtures::client(['name' => '<b>Evil</b> App', 'type' => $type, 'redirectUris' => $redirects]),
            new ResourceOwner('42', 'Ada & Co'),
            Fixtures::resources()->defaultResource(),
            ['content:read' => 'Read your posts'],
            true,
            $redirects[0],
            '/oauth/authorize',
            ['client_id' => 'abc', 'consent_token' => '1.x"y'],
        );
    }

    public function testConsentPageEscapesAndShowsWhatMatters(): void
    {
        $html = (new HtmlConsentRenderer())->render($this->view());

        $this->assertStringContainsString('&lt;b&gt;Evil&lt;/b&gt; App wants to access Example MCP', $html);
        $this->assertStringContainsString('app.example.com', $html);
        $this->assertStringContainsString('not verified', $html);
        $this->assertStringContainsString('Ada &amp; Co', $html);
        $this->assertStringContainsString('<li>Read your posts</li>', $html);
        $this->assertStringContainsString('Stay connected', $html);
        $this->assertStringContainsString('<form method="post" action="/oauth/authorize">', $html);
        $this->assertStringContainsString('<input type="hidden" name="consent_token" value="1.x&quot;y">', $html);
        $this->assertStringContainsString('name="decision" value="approve"', $html);
        $this->assertStringContainsString('name="decision" value="deny"', $html);
        $this->assertStringNotContainsString('<b>Evil</b>', $html);
    }

    public function testConsentPageNotes(): void
    {
        $html = (new HtmlConsentRenderer())->render($this->view(ClientType::Registered, ['http://127.0.0.1/cb']));

        $this->assertStringNotContainsString('not verified', $html);
        $this->assertStringContainsString('your own computer', $html);
    }

    public function testMessagesCanBeOverridden(): void
    {
        $html = (new HtmlConsentRenderer(new Messages(['consent.approve' => 'Permitir'])))->render($this->view());

        $this->assertStringContainsString('Permitir', $html);
    }

    public function testErrorPage(): void
    {
        $html = (new HtmlErrorPageRenderer())->render(OAuthException::invalidRequest('"redirect_uri" is <wrong>.'));

        $this->assertStringContainsString('Authorization failed', $html);
        $this->assertStringContainsString('&quot;redirect_uri&quot; is &lt;wrong&gt;.', $html);
        $this->assertStringContainsString('invalid_request', $html);
    }

    public function testAnEmptyClientHostFallsBackToTheRedirectTarget(): void
    {
        $html = (new HtmlConsentRenderer())->render($this->view(ClientType::Dynamic, ['com.example.app:/cb']));

        $this->assertStringContainsString('The request comes from com.example.app:/cb.', $html);
        $this->assertStringNotContainsString('comes from .', $html);
    }

    public function testScriptPayloadsAreEscaped(): void
    {
        $view = new ConsentView(
            Fixtures::client(['name' => '<script>alert(1)</script>']),
            new ResourceOwner('42', '<script>u</script>'),
            Fixtures::resources()->defaultResource(),
            ['content:read' => '<script>scope</script>'],
            false,
            'https://app.example.com/cb',
            '/oauth/authorize',
            ['a"><script>' => '"><script>v</script>'],
        );

        $html = (new HtmlConsentRenderer())->render($view);

        $this->assertStringNotContainsString('<script', $html);
        $this->assertStringContainsString('&lt;script&gt;scope&lt;/script&gt;', $html);
    }
}
