<?php
declare(strict_types=1);

/**
 * Registers a public client for http://127.0.0.1/callback (any port), gives alice consent for the
 * default scopes, and prints the client id. Usage: php examples/standalone/setup.php [name]
 */

use CakeDC\OAuth\Server\Client\ApplicationType;

['server' => $server, 'users' => $users] = require __DIR__ . '/bootstrap.php';

$created = $server->clientRegistrar()->create(
    $argv[1] ?? 'Demo client',
    ['http://127.0.0.1/callback'],
    false,
    applicationType: ApplicationType::Native,
);
$resource = $server->config()->resources->defaultResource();
$alice = $users->findBySubject('alice');
if ($alice !== null) {
    $server->consentService()->grant($alice, $created['client'], $resource, $resource->defaultScopes);
}
echo $created['client']->clientId;
