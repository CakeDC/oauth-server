<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\View;

/**
 * Optional for an error page renderer: renders the page shown instead of an automatic redirect when a
 * failed request would go to a redirect URI the server does not trust (a dynamically registered or
 * metadata document client the person never approved). An `ErrorPageRendererInterface` that does not
 * implement it shows its plain error page there, without the link.
 */
interface RedirectNoticeRendererInterface
{
    /**
     * The page HTML. It names `$view->redirectHost()` and offers `$view->continueUrl` as a plain link the
     * person may follow; it must never follow it by itself (no script, no meta refresh).
     */
    public function renderRedirectNotice(RedirectNoticeView $view): string;
}
