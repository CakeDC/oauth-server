<?php
declare(strict_types=1);

/**
 * Registers a public native client for http://127.0.0.1/callback (any port) and prints the client id.
 * Usage: php examples/standalone/setup.php [name]
 *
 * A public loopback client is asked for consent on every authorization (RFC 8252 section 8.6), so no
 * consent is recorded here.
 */

use CakeDC\OAuth\Server\Client\ApplicationType;

['server' => $server] = require __DIR__ . '/bootstrap.php';

$created = $server->clientRegistrar()->create(
    $argv[1] ?? 'Demo client',
    ['http://127.0.0.1/callback'],
    false,
    applicationType: ApplicationType::Native,
);
echo $created['client']->clientId;
