<?php
declare(strict_types=1);

/**
 * A plain PHP front controller. Run: php -S 127.0.0.1:8090 examples/standalone/server.php
 */

use CakeDC\OAuth\Server\Owner\ResourceOwner;
use Nyholm\Psr7\Response;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

session_start();
['server' => $server, 'factory' => $factory, 'issuer' => $issuer] = require __DIR__ . '/bootstrap.php';

$request = $factory->createServerRequest($_SERVER['REQUEST_METHOD'], $issuer . $_SERVER['REQUEST_URI'], $_SERVER);
foreach (getallheaders() as $name => $value) {
    $request = $request->withHeader($name, $value);
}
$request = $request
    ->withBody($factory->createStream((string)file_get_contents('php://input')))
    ->withQueryParams($_GET)
    ->withParsedBody($_POST);

$config = $server->config();
$path = $request->getUri()->getPath();
$me = new class implements RequestHandlerInterface {
    /**
     * Answers with the owner of the bearer token.
     */
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $owner = $request->getAttribute(ResourceOwner::class);

        return new Response(200, ['Content-Type' => 'application/json'], (string)json_encode([
            'subject' => $owner?->subject,
            'name' => $owner?->displayName,
        ]));
    }
};

$response = match (true) {
    $path === $config->metadataPath() => $server->metadataHandler()->handle($request),
    $path === $config->endpointPath('authorize') => $server->authorizeHandler()->handle($request),
    $path === $config->endpointPath('token') => $server->tokenHandler()->handle($request),
    $path === $config->endpointPath('register') => $server->registerHandler()->handle($request),
    $path === $config->endpointPath('revoke') => $server->revokeHandler()->handle($request),
    $path === $config->endpointPath('introspect') => $server->introspectHandler()->handle($request),
    $path === $config->endpointPath('connections') => $server->connectionsHandler()->handle($request),
    $path === '/api/me' => $server->bearerMiddleware($issuer . '/api')->process($request, $me),
    $path === '/login' && $request->getMethod() === 'POST' => (function () use ($request): ResponseInterface {
        $body = (array)$request->getParsedBody();
        $_SESSION['user'] = (string)($body['user'] ?? '');
        $return = (string)($request->getQueryParams()['return'] ?? '/oauth/connections');
        // Only local paths: "//host" and "/\host" would leave the site.
        $local = preg_match('#\A/(?![/\\\\])#', $return) === 1;

        return new Response(302, ['Location' => $local ? $return : '/']);
    })(),
    $path === '/login' => new Response(200, ['Content-Type' => 'text/html'], '<form method="post">'
        . '<select name="user"><option value="alice">Alice</option><option value="bob">Bob</option></select>'
        . '<button>Sign in</button></form>'),
    default => new Response(404, [], 'Not found'),
};

http_response_code($response->getStatusCode());
foreach ($response->getHeaders() as $name => $values) {
    foreach ($values as $value) {
        header($name . ': ' . $value, false);
    }
}
echo $response->getBody();
