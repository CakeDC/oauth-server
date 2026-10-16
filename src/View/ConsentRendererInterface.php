<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\View;

/**
 * Renders the consent page.
 */
interface ConsentRendererInterface
{
    /**
     * The page HTML. It must post `$view->fields` and a `decision` of `approve` or `deny` to
     * `$view->formAction`.
     */
    public function render(ConsentView $view): string;
}
