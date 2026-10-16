<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\View;

/**
 * The texts of the built-in pages, in English. Pass overrides to translate or reword them.
 */
final class Messages
{
    public const DEFAULTS = [
        'consent.title' => 'Authorize {client}',
        'consent.heading' => '{client} wants to access {resource}',
        'consent.from' => 'The request comes from {host}. Your answer is sent to {redirect}.',
        'client.local' => 'An application on this computer',
        'consent.fromLocal' => 'The request comes from an application on this computer. Your answer is sent to '
            . '{redirect}.',
        'consent.declaredName' => 'It calls itself {name}. Anyone can choose that name.',
        'consent.unverified' => 'This application registered itself; its name is not verified.',
        'consent.loopback' => 'Only continue if you just started this from an application on this computer: '
            . 'any program on this computer can use this address.',
        'consent.approvedBefore' => 'You approved this application before. It is asked again because its '
            . 'identity cannot be confirmed: only continue if you started this yourself.',
        'consent.user' => 'Signed in as {user}.',
        'consent.scopes' => 'It will be able to:',
        'consent.offline' => 'Stay connected until you revoke it.',
        'consent.approve' => 'Allow',
        'consent.deny' => 'Deny',
        'error.title' => 'Authorization failed',
        'error.intro' => 'The application sent a request that cannot be completed.',
        'error.untrusted' => 'The application asked to send this answer to {host}. This server cannot confirm '
            . 'that {host} belongs to it: only continue if you trust it.',
        'error.continue' => 'Continue to {host}',
        'connections.title' => 'Connected applications',
        'connections.empty' => 'No application is connected.',
        'connections.client' => 'Application',
        'connections.resource' => 'Access to',
        'connections.scopes' => 'Permissions',
        'connections.connected' => 'Connected',
        'connections.lastUsed' => 'Last used',
        'connections.never' => 'Never',
        'connections.revoke' => 'Revoke',
        'connections.hostsAndLocal' => '{hosts} and an application on this computer',
        'connections.unverified' => 'Unverified: this application registered itself.',
        'tokens.title' => 'Personal access tokens',
        'tokens.empty' => 'You have no personal access tokens.',
        'tokens.name' => 'Name',
        'tokens.resource' => 'Resource',
        'tokens.scopes' => 'Permissions',
        'tokens.expires' => 'Expires',
        'tokens.days' => 'Expires in (days, up to {max})',
        'tokens.create' => 'Create token',
        'tokens.created' => 'Copy your new token now. It will not be shown again:',
        'tokens.revoke' => 'Revoke',
    ];

    /**
     * @param array<string, string> $overrides Key => text.
     */
    public function __construct(private readonly array $overrides = [])
    {
    }

    /**
     * The text for $key with `{name}` placeholders replaced.
     *
     * @param array<string, string> $vars Placeholder values.
     */
    public function get(string $key, array $vars = []): string
    {
        $text = $this->overrides[$key] ?? self::DEFAULTS[$key] ?? $key;
        $replace = [];
        foreach ($vars as $name => $value) {
            $replace['{' . $name . '}'] = $value;
        }

        return strtr($text, $replace);
    }
}
