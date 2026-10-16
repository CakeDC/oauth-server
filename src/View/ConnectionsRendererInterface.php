<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\View;

/**
 * Renders the connections page.
 */
interface ConnectionsRendererInterface
{
    /**
     * The page HTML.
     */
    public function render(ConnectionsView $view): string;
}
