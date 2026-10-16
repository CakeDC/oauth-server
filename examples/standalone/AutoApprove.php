<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Example;

use CakeDC\OAuth\Server\View\ConsentRendererInterface;
use CakeDC\OAuth\Server\View\ConsentView;
use CakeDC\OAuth\Server\View\Html\HtmlConsentRenderer;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * UNSAFE, for the conformance run only (`OAUTH_EXAMPLE_AUTO_APPROVE=1`): answers every consent page
 * with "Allow", as if the signed-in person had clicked it.
 *
 * The conformance runner has no person to click, and a public loopback client is asked every time
 * (RFC 8252 section 8.6), so the run needs this. With it on, any page or program that opens an
 * authorization URL gets a code for the signed-in person without them seeing anything. Never enable it
 * on a host anyone else can reach, and never copy it into an application.
 */
final class AutoApprove implements ConsentRendererInterface
{
    private ?ConsentView $shown = null;

    /**
     * @param \Psr\Http\Message\StreamFactoryInterface $streams Builds the posted form body.
     * @param \CakeDC\OAuth\Server\View\ConsentRendererInterface $page The consent page it records.
     */
    public function __construct(
        private readonly StreamFactoryInterface $streams,
        private readonly ConsentRendererInterface $page = new HtmlConsentRenderer(),
    ) {
    }

    /**
     * @inheritDoc
     */
    public function render(ConsentView $view): string
    {
        $this->shown = $view;

        return $this->page->render($view);
    }

    /**
     * Passes $request to the authorization endpoint; when it answers with the consent page, posts that
     * page's form back with "Allow" and returns the endpoint's answer to that.
     */
    public function handle(RequestHandlerInterface $authorize, ServerRequestInterface $request): ResponseInterface
    {
        $this->shown = null;
        $response = $authorize->handle($request);
        $view = $this->shown;
        if ($request->getMethod() !== 'GET' || $view === null || $response->getStatusCode() !== 200) {
            return $response;
        }
        $fields = $view->fields + ['decision' => 'approve'];
        $post = $request
            ->withMethod('POST')
            ->withUri($request->getUri()->withPath($view->formAction)->withQuery(''))
            ->withQueryParams([])
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withBody($this->streams->createStream(http_build_query($fields, '', '&', PHP_QUERY_RFC3986)))
            ->withParsedBody($fields);

        return $authorize->handle($post);
    }
}
