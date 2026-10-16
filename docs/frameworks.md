# Frameworks

The library speaks PSR-7 and PSR-15 and nothing else. Any framework that can route a request to a
`RequestHandlerInterface`, or convert its request to PSR-7, can host it. The rules are the same
everywhere:

1. Build the `AuthorizationServer` once (a service in your container).
2. Route the seven paths from [installation](installation.md#route-the-endpoints) to the handlers.
3. Protect your API routes with `bearerMiddleware()`.
4. Exempt the client-facing endpoints from CSRF protection (see below).
5. Make `UserContextInterface` read the framework's own session and login.

## CSRF exemptions

OAuth clients are programs. They cannot send your CSRF token.

| Path | CSRF middleware |
| --- | --- |
| `/oauth/token`, `/oauth/register`, `/oauth/revoke`, `/oauth/introspect` | Exempt. They are called by clients, and they authenticate with codes, secrets and tokens |
| `/.well-known/oauth-authorization-server` | Exempt (read only) |
| `/oauth/authorize` (POST), `/oauth/connections` (POST) | Exempt. The built-in forms carry their own signed `consent_token` or `form_token`, bound to the request and to the signed-in person, and the library verifies it. A framework CSRF check that wants its own field would reject the built-in forms |
| Your API routes | Do not apply cookie based CSRF protection. They use bearer tokens, not cookies |

If you replace the pages with your own renderers ([pages](pages.md)) you keep posting the same token
fields, so the same rule holds.

## Sessions

`UserContextInterface::currentOwner()` must see the same login your site uses. In a framework, read
the framework's authentication, not the PSR-7 request. A PSR-7 request converted by a bridge does not
carry the framework's session object.

The authorize and connections routes must therefore run with the session started (the `web` middleware
group in Laravel, the default firewall in Symfony, the session middleware in Slim and Mezzio).

## Plain PHP

`examples/standalone/server.php` is a complete front controller. It builds a PSR-7 request with
`nyholm/psr7`, matches paths with `match (true)`, runs the handlers and emits the response, header by
header, with `header($name . ': ' . $value, false)` so a handler's `Set-Cookie` never replaces the
session cookie. Run it with `php -S 127.0.0.1:8090 examples/standalone/server.php` (see
`examples/standalone/README.md`).

## Slim 4

```php
use Psr\Http\Message\ServerRequestInterface;
use Slim\Factory\AppFactory;

$app = AppFactory::create();
$config = $server->config();

$app->get($config->metadataPath(), fn (ServerRequestInterface $r) => $server->metadataHandler()->handle($r));
$app->map(['GET', 'POST'], $config->endpointPath('authorize'), fn (ServerRequestInterface $r) => $server->authorizeHandler()->handle($r));
$app->map(['POST', 'OPTIONS'], $config->endpointPath('token'), fn (ServerRequestInterface $r) => $server->tokenHandler()->handle($r));
$app->map(['POST', 'OPTIONS'], $config->endpointPath('register'), fn (ServerRequestInterface $r) => $server->registerHandler()->handle($r));
$app->map(['POST', 'OPTIONS'], $config->endpointPath('revoke'), fn (ServerRequestInterface $r) => $server->revokeHandler()->handle($r));
$app->map(['POST', 'OPTIONS'], $config->endpointPath('introspect'), fn (ServerRequestInterface $r) => $server->introspectHandler()->handle($r));
$app->map(['GET', 'POST'], $config->endpointPath('connections'), fn (ServerRequestInterface $r) => $server->connectionsHandler()->handle($r));

// A protected API route.
$app->get('/api/me', MeAction::class)->add($server->bearerMiddleware('https://auth.example.com/api'));

$app->run();
```

Add Slim's session middleware to the app (not to the token routes). If you use `slim/csrf`, add its
guard to your own HTML routes only, or give it a path exemption.

## Mezzio

Mezzio accepts request handler instances, so the routes are one line each:

```php
$config = $server->config();
$app->get($config->metadataPath(), $server->metadataHandler(), 'oauth.metadata');
$app->route($config->endpointPath('authorize'), $server->authorizeHandler(), ['GET', 'POST'], 'oauth.authorize');
$app->route($config->endpointPath('token'), $server->tokenHandler(), ['POST', 'OPTIONS'], 'oauth.token');
$app->route($config->endpointPath('register'), $server->registerHandler(), ['POST', 'OPTIONS'], 'oauth.register');
$app->route($config->endpointPath('revoke'), $server->revokeHandler(), ['POST', 'OPTIONS'], 'oauth.revoke');
$app->route($config->endpointPath('introspect'), $server->introspectHandler(), ['POST', 'OPTIONS'], 'oauth.introspect');
$app->route($config->endpointPath('connections'), $server->connectionsHandler(), ['GET', 'POST'], 'oauth.connections');

// A protected API route.
$app->get('/api/me', [$server->bearerMiddleware('https://auth.example.com/api'), MeHandler::class], 'api.me');
```

Register `AuthorizationServer` with a factory in your container, injecting the PSR-17 factories Mezzio
already has. Put the session middleware (for example `mezzio-session`) in the pipeline of the authorize
and connections routes.

## Symfony

Use `symfony/psr-http-message-bridge` and `nyholm/psr7` to convert between HttpFoundation and PSR-7.
Register `AuthorizationServer` as a service, and write one controller:

```php
use CakeDC\OAuth\Server\AuthorizationServer;
use Psr\Http\Server\RequestHandlerInterface;
use Symfony\Bridge\PsrHttpMessage\HttpFoundationFactoryInterface;
use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class OAuthController
{
    public function __construct(
        private readonly AuthorizationServer $server,
        private readonly HttpMessageFactoryInterface $psrFactory,
        private readonly HttpFoundationFactoryInterface $foundationFactory,
    ) {
    }

    #[Route('/.well-known/oauth-authorization-server', methods: ['GET', 'OPTIONS'])]
    public function metadata(Request $request): Response
    {
        return $this->run($this->server->metadataHandler(), $request);
    }

    #[Route('/oauth/authorize', methods: ['GET', 'POST'])]
    public function authorize(Request $request): Response
    {
        return $this->run($this->server->authorizeHandler(), $request);
    }

    #[Route('/oauth/token', methods: ['POST', 'OPTIONS'])]
    public function token(Request $request): Response
    {
        return $this->run($this->server->tokenHandler(), $request);
    }

    // register, revoke, introspect and connections follow the same pattern.

    private function run(RequestHandlerInterface $handler, Request $request): Response
    {
        return $this->foundationFactory->createResponse($handler->handle($this->psrFactory->createRequest($request)));
    }
}
```

`currentOwner()` reads the user from `Symfony\Bundle\SecurityBundle\Security::getUser()` and
`loginResponse()` returns a PSR-7 redirect to your login route with the return URL. Symfony's CSRF
protection only applies to forms that use it, so nothing needs exempting, but the authorize and
connections routes must be inside a firewall that starts the session.

## Laravel

Laravel uses the same bridge: `symfony/psr-http-message-bridge` and `nyholm/psr7`. Bind
`AuthorizationServer` in a service provider, then route it:

```php
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

$run = fn (string $handler) => fn (Request $request) => $foundation->createResponse(
    $server->$handler()->handle($psr->createRequest($request)),
);

Route::match(['GET', 'OPTIONS'], '/.well-known/oauth-authorization-server', $run('metadataHandler'));
Route::match(['GET', 'POST'], '/oauth/authorize', $run('authorizeHandler'))->middleware('web');
Route::match(['POST', 'OPTIONS'], '/oauth/token', $run('tokenHandler'));
Route::match(['GET', 'POST'], '/oauth/connections', $run('connectionsHandler'))->middleware('web');
// register, revoke and introspect are like token.
```

(`$server`, `$psr` and `$foundation` come from the container.) Exempt the paths from CSRF in
`bootstrap/app.php`:

```php
->withMiddleware(function (Middleware $middleware) {
    $middleware->validateCsrfTokens(except: ['oauth/*']);
})
```

`currentOwner()` returns an owner built from `Auth::user()`. `loginResponse()` returns a PSR-7
redirect to your login with the return URL in the query or the session's intended URL. Protect
your API routes by converting them in the same way and wrapping the handler with
`$server->bearerMiddleware($resource)`, or validate directly with
[`TokenValidator`](protecting-resources.md#using-tokenvalidator-directly) in a Laravel middleware.

## Frameworks with their own HTTP layer

The handlers return PSR-7 responses with a status, headers and a body. Whatever your framework needs
to send them, copy all three. Do not add cache headers to the token endpoint's answers, and do not
replace `Set-Cookie` headers.
