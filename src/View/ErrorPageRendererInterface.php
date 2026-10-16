<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\View;

use CakeDC\OAuth\Server\Exception\OAuthException;

/**
 * Renders the page shown when an authorization request cannot go back to its client.
 */
interface ErrorPageRendererInterface
{
    /**
     * The page HTML.
     */
    public function render(OAuthException $error): string;
}
