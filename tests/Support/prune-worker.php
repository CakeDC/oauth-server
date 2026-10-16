<?php
declare(strict_types=1);

/**
 * Runs PdoStorage::prune() in a process (and a database connection) of its own, for PruneLockTest. It
 * prints its connection id first, so the test can see when it waits on a lock, then the prune result.
 * The connection comes from OAUTH_PRUNE_DSN, OAUTH_PRUNE_USER and OAUTH_PRUNE_PASSWORD; the clock from
 * the first argument.
 */

use CakeDC\OAuth\Server\Storage\Pdo\PdoStorage;

require dirname(__DIR__, 2) . '/vendor/autoload.php';

$pdo = new PDO(
    (string)getenv('OAUTH_PRUNE_DSN'),
    (string)getenv('OAUTH_PRUNE_USER'),
    (string)getenv('OAUTH_PRUNE_PASSWORD'),
);
$driver = $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
$id = $pdo->query($driver === 'pgsql' ? 'SELECT pg_backend_pid()' : 'SELECT CONNECTION_ID()');
fwrite(STDOUT, ($id === false ? '' : (string)$id->fetchColumn()) . "\n");
fflush(STDOUT);

$result = (new PdoStorage($pdo))->prune(new DateTimeImmutable($argv[1] ?? 'now'), 7 * 86400, 30 * 86400);
fwrite(STDOUT, (string)json_encode([
    'codes' => $result->codes,
    'tokens' => $result->tokens,
    'clients' => $result->clients,
]) . "\n");
