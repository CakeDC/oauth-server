<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\View\Html;

use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\View\ErrorPageRendererInterface;
use CakeDC\OAuth\Server\View\Messages;

/**
 * The built-in error page.
 */
final class HtmlErrorPageRenderer implements ErrorPageRendererInterface
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
        $body = '<h1>' . Html::e($this->messages->get('error.title')) . '</h1>'
            . '<p>' . Html::e($this->messages->get('error.intro')) . '</p>'
            . '<p>' . Html::e($error->getMessage()) . '</p>'
            . '<p class="muted"><code>' . Html::e($error->error) . '</code></p>';

        return Html::page($this->messages->get('error.title'), $body);
    }
}
