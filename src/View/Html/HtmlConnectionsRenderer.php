<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\View\Html;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Client\ClientType;
use CakeDC\OAuth\Server\View\ConnectionsRendererInterface;
use CakeDC\OAuth\Server\View\ConnectionsView;
use CakeDC\OAuth\Server\View\Messages;
use DateTimeImmutable;

/**
 * The built-in connections page.
 */
final class HtmlConnectionsRenderer implements ConnectionsRendererInterface
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
    public function render(ConnectionsView $view): string
    {
        $m = $this->messages;
        $body = '<h1>' . Html::e($m->get('connections.title')) . '</h1>';
        if ($view->error !== null) {
            $body .= '<p class="warning">' . Html::e($view->error) . '</p>';
        }
        if ($view->connections === []) {
            $body .= '<p class="muted">' . Html::e($m->get('connections.empty')) . '</p>';
        } else {
            $body .= '<table><tr><th>' . Html::e($m->get('connections.client')) . '</th><th>'
                . Html::e($m->get('connections.resource')) . '</th><th>' . Html::e($m->get('connections.scopes'))
                . '</th><th>' . Html::e($m->get('connections.connected')) . '</th><th>'
                . Html::e($m->get('connections.lastUsed')) . '</th><th></th></tr>';
            foreach ($view->connections as $connection) {
                $body .= '<tr><td>' . $this->client($connection->client) . '</td><td>'
                    . Html::e($view->resourceName($connection->resource)) . '</td><td>'
                    . Html::e(implode(', ', $connection->scopes)) . '</td><td>'
                    . Html::e($this->date($connection->connectedAt)) . '</td><td>'
                    . Html::e($this->date($connection->lastUsedAt)) . '</td><td>'
                    . $this->form(
                        $view,
                        'revoke_connection',
                        ['family_id' => $connection->familyId],
                        $m->get('connections.revoke'),
                    )
                    . '</td></tr>';
            }
            $body .= '</table>';
        }
        if ($view->personalTokensEnabled || $view->personalTokens !== []) {
            $body .= $this->personalTokens($view);
        }

        return Html::page($m->get('connections.title'), $body);
    }

    /**
     * The client cell: a metadata document is named by its host (its own name is self-asserted) and a
     * registered client is marked unverified.
     */
    private function client(Client $client): string
    {
        $host = $client->displayHost();
        if ($client->type === ClientType::MetadataDocument && $host !== '') {
            return Html::e($host);
        }
        $html = Html::e($client->name) . '<br><span class="muted">' . Html::e($host) . '</span>';
        if ($client->type === ClientType::Dynamic) {
            $html .= '<br><span class="warning">' . Html::e($this->messages->get('connections.unverified'))
                . '</span>';
        }

        return $html;
    }

    /**
     * The personal token section.
     */
    private function personalTokens(ConnectionsView $view): string
    {
        $m = $this->messages;
        $html = '<h2>' . Html::e($m->get('tokens.title')) . '</h2>';
        if ($view->newToken !== null) {
            $html .= '<p class="warning">' . Html::e($m->get('tokens.created')) . '</p><p><code>'
                . Html::e($view->newToken) . '</code></p>';
        }
        if ($view->personalTokens === []) {
            $html .= '<p class="muted">' . Html::e($m->get('tokens.empty')) . '</p>';
        } else {
            $html .= '<table><tr><th>' . Html::e($m->get('tokens.name')) . '</th><th>'
                . Html::e($m->get('tokens.resource')) . '</th><th>'
                . Html::e($m->get('tokens.scopes')) . '</th><th>' . Html::e($m->get('tokens.expires'))
                . '</th><th></th></tr>';
            foreach ($view->personalTokens as $token) {
                $html .= '<tr><td>' . Html::e((string)$token->name) . '</td><td>'
                    . Html::e($view->resourceName($token->resource)) . '</td><td>'
                    . Html::e(implode(', ', $token->scopes)) . '</td><td>'
                    . Html::e($this->date($token->expiresAt)) . '</td><td>'
                    . $this->form($view, 'revoke_token', ['token_id' => $token->id], $m->get('tokens.revoke'))
                    . '</td></tr>';
            }
            $html .= '</table>';
        }
        if ($view->creatable === []) {
            return $html;
        }
        $options = '';
        $scopes = '';
        foreach ($view->creatable as $identifier => $resource) {
            $options .= '<option value="' . Html::e($identifier) . '">' . Html::e($resource['name']) . '</option>';
            $scopes .= '<fieldset><legend>' . Html::e($resource['name']) . '</legend>';
            foreach ($resource['scopes'] as $scope => $description) {
                $scopes .= '<label><input type="checkbox" name="scope:' . Html::e($scope) . '" value="1"> '
                    . Html::e($description) . '</label>';
            }
            $scopes .= '</fieldset>';
        }
        $html .= '<form method="post" action="' . Html::e($view->formAction) . '">'
            . $this->hidden('form_token', $view->formToken) . $this->hidden('action', 'create_token')
            . '<label>' . Html::e($m->get('tokens.name'))
            . ' <input type="text" name="name" maxlength="100" required></label>'
            . '<label>' . Html::e($m->get('tokens.resource'))
            . ' <select name="resource">' . $options . '</select></label>'
            . $scopes
            . '<label>' . Html::e($m->get('tokens.days', ['max' => (string)$view->maxDays]))
            . ' <input type="number" name="days" min="1" max="' . $view->maxDays . '" value="'
            . min(30, $view->maxDays) . '"></label>'
            . '<button type="submit">' . Html::e($m->get('tokens.create')) . '</button></form>';

        return $html;
    }

    /**
     * A one-button form.
     *
     * @param array<string, string> $fields Hidden fields.
     */
    private function form(ConnectionsView $view, string $action, array $fields, string $label): string
    {
        $hidden = $this->hidden('form_token', $view->formToken) . $this->hidden('action', $action);
        foreach ($fields as $name => $value) {
            $hidden .= $this->hidden($name, $value);
        }

        return '<form method="post" action="' . Html::e($view->formAction) . '">' . $hidden
            . '<button type="submit" class="secondary">' . Html::e($label) . '</button></form>';
    }

    /**
     * A hidden input.
     */
    private function hidden(string $name, string $value): string
    {
        return sprintf('<input type="hidden" name="%s" value="%s">', Html::e($name), Html::e($value));
    }

    /**
     * A date for people, or "Never".
     */
    private function date(?DateTimeImmutable $date): string
    {
        return $date === null ? $this->messages->get('connections.never') : $date->format('Y-m-d H:i') . ' UTC';
    }
}
