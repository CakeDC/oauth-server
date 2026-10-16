<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\View\Html;

use CakeDC\OAuth\Server\Client\ClientType;
use CakeDC\OAuth\Server\Connections\Connection;
use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\View\ConnectionsView;
use CakeDC\OAuth\Server\View\ConsentView;
use CakeDC\OAuth\Server\View\Html\Html;
use CakeDC\OAuth\Server\View\Html\HtmlConnectionsRenderer;
use CakeDC\OAuth\Server\View\Html\HtmlConsentRenderer;
use CakeDC\OAuth\Server\View\Html\HtmlErrorPageRenderer;
use CakeDC\OAuth\Server\View\Messages;
use CakeDC\OAuth\Server\View\RedirectNoticeView;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
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

        $this->assertStringContainsString('<h1>app.example.com wants to access Example MCP</h1>', $html);
        $this->assertStringContainsString('calls itself <q>&lt;b&gt;Evil&lt;/b&gt; App</q>', $html);
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
        $this->assertStringContainsString('Only continue if you just started this', $html);
        $this->assertStringNotContainsString('runs on your own computer', $html);
    }

    public function testMessagesCanBeOverridden(): void
    {
        $html = (new HtmlConsentRenderer(new Messages(['consent.approve' => 'Permitir'])))->render($this->view());

        $this->assertStringContainsString('Permitir', $html);
    }

    public function testErrorPage(): void
    {
        $html = (new HtmlErrorPageRenderer())->render(OAuthException::invalidRequest("'redirect_uri' is <wrong>."));

        $this->assertStringContainsString('Authorization failed', $html);
        $this->assertStringContainsString('&#039;redirect_uri&#039; is &lt;wrong&gt;.', $html);
        $this->assertStringContainsString('invalid_request', $html);
    }

    public function testTheRedirectNoticeNamesTheHostAndOnlyLinksToIt(): void
    {
        $view = new RedirectNoticeView(
            OAuthException::invalidRequest("'code_challenge' is <missing>."),
            Fixtures::client(),
            'https://Evil.example/cb',
            'https://evil.example/cb?error=invalid_request&state=%22%3E%3Cscript%3E',
        );

        $html = (new HtmlErrorPageRenderer())->renderRedirectNotice($view);

        $this->assertStringContainsString('Authorization failed', $html);
        $this->assertStringContainsString('&#039;code_challenge&#039; is &lt;missing&gt;.', $html);
        $this->assertStringContainsString('send this answer to evil.example', $html);
        $this->assertStringContainsString(
            '<a href="https://evil.example/cb?error=invalid_request&amp;state=%22%3E%3Cscript%3E" rel="noreferrer">'
                . 'Continue to evil.example</a>',
            $html,
        );
        $this->assertStringNotContainsString('<script', $html);
        $this->assertStringNotContainsString('http-equiv', $html);
    }

    public function testTheRedirectNoticeOfAPrivateSchemeNamesTheScheme(): void
    {
        $renderer = new HtmlErrorPageRenderer(new Messages(['error.continue' => 'Seguir a {host}']));
        foreach (['com.example.app:/cb', 'com.example.app://oauth/cb'] as $uri) {
            $view = new RedirectNoticeView(OAuthException::accessDenied('No.'), null, $uri, $uri . '?error=access_denied');

            $this->assertSame('com.example.app', $view->redirectHost(), $uri);
            $this->assertStringContainsString('Seguir a com.example.app</a>', $renderer->renderRedirectNotice($view), $uri);
        }
    }

    public function testADynamicClientCannotPassForAnotherOneByItsName(): void
    {
        $real = Fixtures::client([
            'type' => ClientType::MetadataDocument,
            'clientId' => 'https://claude.ai/oauth/mcp-oauth-client-metadata',
            'name' => 'Claude',
            'redirectUris' => ['https://claude.ai/api/mcp/auth_callback'],
        ]);
        $fake = Fixtures::client([
            'name' => 'claude.ai',
            'redirectUris' => ['https://claude-ai.example/cb'],
        ]);
        $page = fn($client) => (new HtmlConsentRenderer())->render(new ConsentView(
            $client,
            new ResourceOwner('42', 'Ada'),
            Fixtures::resources()->defaultResource(),
            ['content:read' => 'Read'],
            false,
            $client->redirectUris[0],
            '/oauth/authorize',
            [],
        ));

        $html = $page($fake);

        $this->assertStringContainsString('<title>Authorize claude-ai.example</title>', $html);
        $this->assertStringContainsString('<h1>claude-ai.example wants to access Example MCP</h1>', $html);
        $this->assertStringContainsString('calls itself <q>claude.ai</q>', $html);
        $this->assertStringNotContainsString('<title>Authorize claude.ai</title>', $html);
        $this->assertStringContainsString('<title>Authorize claude.ai</title>', $page($real));
        $this->assertStringNotContainsString('calls itself', $page($real));
    }

    public function testADynamicClientWithoutADeclaredNameShowsNoSecondLine(): void
    {
        $client = Fixtures::client(['name' => 'app.example.com']);
        $html = (new HtmlConsentRenderer())->render(new ConsentView(
            $client,
            new ResourceOwner('42', 'Ada'),
            Fixtures::resources()->defaultResource(),
            [],
            false,
            'https://app.example.com/cb',
            '/oauth/authorize',
            [],
        ));

        $this->assertStringContainsString('<h1>app.example.com wants', $html);
        $this->assertStringNotContainsString('calls itself', $html);
    }

    public function testADynamicClientOfAPrivateSchemeGetsAFixedLabelAndTheSchemeOnlyAsTheDestination(): void
    {
        $html = (new HtmlConsentRenderer())->render($this->view(ClientType::Dynamic, ['com.example.app://oauth/cb']));

        $this->assertStringContainsString('<h1>An application on this computer wants to access Example MCP</h1>', $html);
        $this->assertStringContainsString('Your answer is sent to com.example.app.', $html);
        $this->assertStringNotContainsString('<h1>com.example.app', $html);
    }

    public function testASchemeNamedLikeAnotherClientCannotPassForIt(): void
    {
        $client = Fixtures::client(['name' => 'claude.ai', 'redirectUris' => ['claude.ai:/callback']]);
        $view = new ConsentView(
            $client,
            new ResourceOwner('42', 'Ada'),
            Fixtures::resources()->defaultResource(),
            [],
            false,
            'claude.ai:/callback',
            '/oauth/authorize',
            [],
        );

        $html = (new HtmlConsentRenderer())->render($view);

        $this->assertStringContainsString('<title>Authorize An application on this computer</title>', $html);
        $this->assertStringContainsString('<h1>An application on this computer wants to access', $html);
        $this->assertStringContainsString('The request comes from An application on this computer.', $html);
        $this->assertStringContainsString('Your answer is sent to claude.ai.', $html);
        $this->assertStringContainsString('calls itself <q>claude.ai</q>', $html);
        $this->assertSame('', $view->clientHost());
        $this->assertSame('', $view->clientLabel());
    }

    public function testTheRequestComesFromTheRequestedRedirectNotFromAListedOne(): void
    {
        foreach (
            [
            [['https://claude.ai/api/mcp/auth_callback', 'https://evil.example/cb'], 'https://evil.example/cb'],
            [['com.example.app://claude.ai/cb', 'https://evil.example/cb'], 'https://evil.example/cb'],
            ] as [$registered, $requested]
        ) {
            $client = Fixtures::client(['name' => 'Claude', 'redirectUris' => $registered]);
            $view = new ConsentView(
                $client,
                new ResourceOwner('42', 'Ada'),
                Fixtures::resources()->defaultResource(),
                [],
                false,
                $requested,
                '/oauth/authorize',
                [],
            );

            $html = (new HtmlConsentRenderer())->render($view);

            $this->assertStringContainsString('The request comes from evil.example. Your answer is sent to evil.example.', $html);
            $this->assertSame('evil.example', $view->clientHost());
        }
    }

    public function testATemplateWithoutThePlaceholderStillShowsTheName(): void
    {
        $this->assertSame(
            'Calls itself &lt;x&gt; <q>A &amp; B</q>',
            Html::withQuotedName('Calls itself <x>', 'A & B'),
        );
        $this->assertSame('a <q>N</q> b', Html::withQuotedName('a {name} b', 'N'));

        $page = (new HtmlConsentRenderer(new Messages(['consent.declaredName' => 'Self-declared'])))
            ->render($this->view());
        $this->assertStringContainsString('Self-declared <q>&lt;b&gt;Evil&lt;/b&gt; App</q>', $page);
    }

    public function testANameCannotCloseItsQuoteAndSpeakForTheServer(): void
    {
        $name = 'Claude". Verified publisher. "';
        $client = Fixtures::client(['name' => $name]);
        $view = new ConsentView(
            $client,
            new ResourceOwner('42', 'Ada'),
            Fixtures::resources()->defaultResource(),
            [],
            false,
            'https://app.example.com/cb',
            '/oauth/authorize',
            [],
        );

        $html = (new HtmlConsentRenderer())->render($view);

        $this->assertStringContainsString('<q>Claude&quot;. Verified publisher. &quot;</q>. Anyone can choose that name.', $html);
    }

    public function testTheConnectionsPageNamesDynamicClientsByHostAndQuotesTheirName(): void
    {
        $page = function (array $overrides): string {
            $client = Fixtures::client($overrides);

            $connection = new Connection(
                'fam',
                $client,
                Fixtures::MCP,
                ['content:read'],
                new DateTimeImmutable('2026-01-01'),
                null,
            );

            return (new HtmlConnectionsRenderer())->render(
                new ConnectionsView(new ResourceOwner('42', 'Ada'), [$connection], [], [], [], '/c', 'tok', 30, false),
            );
        };

        $web = $page(['name' => 'claude.ai', 'redirectUris' => ['https://evil.example/cb']]);
        $this->assertStringContainsString('<td>evil.example<br>', $web);
        $this->assertStringContainsString('<q>claude.ai</q>', $web);

        $local = $page(['name' => 'claude.ai', 'redirectUris' => ['claude.ai:/callback']]);
        $this->assertStringContainsString('<td>An application on this computer<br>', $local);
        $this->assertStringContainsString('<q>claude.ai</q>', $local);

        $mixed = $page(['name' => 'Claude', 'redirectUris' => ['https://example.com/cb', 'claude.ai:/callback']]);
        $this->assertStringContainsString('<td>example.com and an application on this computer<br>', $mixed);
        $this->assertStringContainsString('<q>Claude</q>', $mixed);
        $this->assertStringContainsString('registered itself', $mixed);
    }

    public function testBothViewsNameTheRedirectTargetTheSameWay(): void
    {
        foreach (['https://App.example.com/cb', 'com.example.app:/cb', 'com.example.app://oauth/cb', 'http://127.0.0.1:5/cb'] as $uri) {
            $consent = $this->view(ClientType::Dynamic, [$uri]);
            $notice = new RedirectNoticeView(OAuthException::accessDenied('No.'), null, $uri, $uri);

            $this->assertSame($notice->redirectHost(), $consent->redirectHost(), $uri);
        }
        $this->assertSame('com.example.app', $this->view(ClientType::Dynamic, ['com.example.app://oauth/cb'])->redirectHost());
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function remembered(): array
    {
        return [
            'loopback' => ['http://127.0.0.1:51000/cb', true],
            'loopback range' => ['https://127.0.0.5/cb', true],
            '.localhost name' => ['https://app.localhost/cb', true],
            'unspecified address' => ['https://0.0.0.0/cb', true],
            'private scheme' => ['com.example.app:/cb', true],
            'remote https' => ['https://app.example.com/cb', false],
        ];
    }

    #[DataProvider('remembered')]
    public function testThePageWarnsWheneverTheRememberedConsentIsNotEnough(string $uri, bool $warns): void
    {
        $base = $this->view(ClientType::Dynamic, [$uri]);
        $view = new ConsentView(
            $base->client,
            $base->owner,
            $base->resource,
            $base->scopes,
            $base->offlineAccess,
            $base->redirectUri,
            $base->formAction,
            $base->fields,
            true,
        );

        $html = (new HtmlConsentRenderer())->render($view);

        $this->assertSame($warns, str_contains($html, 'any program on this computer'), $uri);
        $this->assertStringContainsString('approved this application before', $html);
    }

    public function testTheApprovedBeforeLine(): void
    {
        $view = $this->view(ClientType::MetadataDocument, ['http://127.0.0.1/cb']);
        $again = new ConsentView(
            $view->client,
            $view->owner,
            $view->resource,
            $view->scopes,
            $view->offlineAccess,
            $view->redirectUri,
            $view->formAction,
            $view->fields,
            true,
        );

        $this->assertStringNotContainsString('approved this application before', (new HtmlConsentRenderer())->render($view));
        $this->assertStringContainsString('approved this application before', (new HtmlConsentRenderer())->render($again));
    }

    public function testAPrivateSchemeIsShownAsTheDestinationAndNeverAsTheRequester(): void
    {
        $html = (new HtmlConsentRenderer())->render($this->view(ClientType::Dynamic, ['com.example.app:/cb']));

        $this->assertStringContainsString('The request comes from An application on this computer.', $html);
        $this->assertStringContainsString('Your answer is sent to com.example.app.', $html);
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
