<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\View\Html;

use CakeDC\OAuth\Server\Client\ClientType;
use CakeDC\OAuth\Server\View\ConsentRendererInterface;
use CakeDC\OAuth\Server\View\ConsentView;
use CakeDC\OAuth\Server\View\Messages;

/**
 * The built-in consent page.
 */
final class HtmlConsentRenderer implements ConsentRendererInterface
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
    public function render(ConsentView $view): string
    {
        $m = $this->messages;
        $items = '';
        foreach ($view->scopes as $description) {
            $items .= '<li>' . Html::e($description) . '</li>';
        }
        if ($view->offlineAccess) {
            $items .= '<li>' . Html::e($m->get('consent.offline')) . '</li>';
        }
        $notes = '';
        if ($view->isUnverified()) {
            $notes .= '<p class="warning">' . Html::e($m->get('consent.unverified')) . '</p>';
        }
        if ($view->isLoopbackOnly()) {
            $notes .= '<p class="warning">' . Html::e($m->get('consent.loopback')) . '</p>';
        }
        if ($view->approvedBefore) {
            $notes .= '<p class="warning">' . Html::e($m->get('consent.approvedBefore')) . '</p>';
        }
        $fields = '';
        foreach ($view->fields as $name => $value) {
            $fields .= sprintf('<input type="hidden" name="%s" value="%s">', Html::e($name), Html::e($value));
        }
        // A name is self-asserted, so the title and the heading use a host the client cannot choose freely.
        $client = $view->clientLabel() !== '' ? $view->clientLabel() : $m->get('client.local');
        $from = $m->get('consent.from', [
            'host' => $view->clientHost() !== '' ? $view->clientHost() : $view->redirectHost(),
            'redirect' => $view->redirectHost(),
        ]);
        if ($view->client->type === ClientType::Dynamic && $view->clientHost() === '') {
            // The scheme of a private-use redirect is chosen by the client: it is shown only as the destination.
            $from = $m->get('consent.fromLocal', ['redirect' => $view->redirectHost()]);
        }
        $declared = $view->declaredName();
        if ($declared !== null) {
            $notes = '<p class="muted">' . Html::withQuotedName($m->get('consent.declaredName'), $declared)
                . '</p>' . $notes;
        }
        $body = '<h1>' . Html::e($m->get('consent.heading', [
                'client' => $client,
                'resource' => $view->resource->name,
            ])) . '</h1>'
            . '<p class="muted">' . Html::e($from) . '</p>'
            . $notes
            . '<p>' . Html::e($m->get('consent.user', ['user' => $view->owner->displayName])) . '</p>'
            . '<p>' . Html::e($m->get('consent.scopes')) . '</p><ul>' . $items . '</ul>'
            . '<form method="post" action="' . Html::e($view->formAction) . '">' . $fields
            . '<button type="submit" name="decision" value="approve">'
            . Html::e($m->get('consent.approve')) . '</button> '
            . '<button type="submit" name="decision" value="deny" class="secondary">'
            . Html::e($m->get('consent.deny')) . '</button></form>';

        return Html::page($m->get('consent.title', ['client' => $client]), $body);
    }
}
