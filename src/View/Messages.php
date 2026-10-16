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
        'consent.unverified' => 'This application registered itself; its name is not verified.',
        'consent.loopback' => 'This application runs on your own computer.',
        'consent.user' => 'Signed in as {user}.',
        'consent.scopes' => 'It will be able to:',
        'consent.offline' => 'Stay connected until you revoke it.',
        'consent.approve' => 'Allow',
        'consent.deny' => 'Deny',
        'error.title' => 'Authorization failed',
        'error.intro' => 'The application sent a request that cannot be completed.',
        'connections.title' => 'Connected applications',
        'connections.empty' => 'No application is connected.',
        'connections.client' => 'Application',
        'connections.resource' => 'Access to',
        'connections.scopes' => 'Permissions',
        'connections.connected' => 'Connected',
        'connections.lastUsed' => 'Last used',
        'connections.never' => 'Never',
        'connections.revoke' => 'Revoke',
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
