<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\View\Html;

use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\View\ErrorPageRendererInterface;
use CakeDC\OAuth\Server\View\Messages;
use CakeDC\OAuth\Server\View\RedirectNoticeRendererInterface;
use CakeDC\OAuth\Server\View\RedirectNoticeView;

/**
 * The built-in error page, with or without the link back to an untrusted client.
 */
final class HtmlErrorPageRenderer implements ErrorPageRendererInterface, RedirectNoticeRendererInterface
{
    /**
     * @param \CakeDC\OAuth\Server\View\Messages $messages Texts.
     */
    public function __construct(private readonly Messages $messages = new Messages())
    {
    }

    /**
     * @inheritDoc
     */
    public function render(OAuthException $error): string
    {
        return Html::page($this->messages->get('error.title'), $this->body($error));
    }

    /**
     * @inheritDoc
     */
    public function renderRedirectNotice(RedirectNoticeView $view): string
    {
        $host = $view->redirectHost();
        $body = $this->body($view->error)
            . '<p class="warning">' . Html::e($this->messages->get('error.untrusted', ['host' => $host])) . '</p>'
            . '<p><a href="' . Html::e($view->continueUrl) . '" rel="noreferrer">'
            . Html::e($this->messages->get('error.continue', ['host' => $host])) . '</a></p>';

        return Html::page($this->messages->get('error.title'), $body);
    }

    /**
     * The title, the explanation and the error.
     */
    private function body(OAuthException $error): string
    {
        return '<h1>' . Html::e($this->messages->get('error.title')) . '</h1>'
            . '<p>' . Html::e($this->messages->get('error.intro')) . '</p>'
            . '<p>' . Html::e($error->getMessage()) . '</p>'
            . '<p class="muted"><code>' . Html::e($error->error) . '</code></p>';
    }
}
