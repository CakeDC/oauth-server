<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Http\Handler;

use CakeDC\OAuth\Server\Client\GrantType;
use CakeDC\OAuth\Server\Config\ServerConfig;
use CakeDC\OAuth\Server\Event\AuthorizationDenied;
use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Grant\AuthorizationError;
use CakeDC\OAuth\Server\Grant\AuthorizationRequest;
use CakeDC\OAuth\Server\Grant\AuthorizationRequestValidator;
use CakeDC\OAuth\Server\Grant\CodeIssuer;
use CakeDC\OAuth\Server\Grant\ConsentService;
use CakeDC\OAuth\Server\Grant\RedirectUrl;
use CakeDC\OAuth\Server\Http\FormBody;
use CakeDC\OAuth\Server\Http\HttpResponder;
use CakeDC\OAuth\Server\Http\Params;
use CakeDC\OAuth\Server\Http\RequestPath;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Owner\UserContextInterface;
use CakeDC\OAuth\Server\Owner\UserProviderInterface;
use CakeDC\OAuth\Server\RateLimit\RateLimiter;
use CakeDC\OAuth\Server\Scope\ScopeResolver;
use CakeDC\OAuth\Server\Scope\Scopes;
use CakeDC\OAuth\Server\Security\FormToken;
use CakeDC\OAuth\Server\View\ConsentRendererInterface;
use CakeDC\OAuth\Server\View\ConsentView;
use CakeDC\OAuth\Server\View\ErrorPageRendererInterface;
use Closure;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * The authorization endpoint: login hand-off, consent page and the decision.
 */
final class AuthorizeHandler implements RequestHandlerInterface
{
    /**
     * @param \CakeDC\OAuth\Server\Config\ServerConfig $config Settings.
     * @param \CakeDC\OAuth\Server\Grant\AuthorizationRequestValidator $validator Request validation.
     * @param \CakeDC\OAuth\Server\Owner\UserContextInterface $userContext The signed-in person.
     * @param \CakeDC\OAuth\Server\Owner\UserProviderInterface $users The application's people.
     * @param \CakeDC\OAuth\Server\Scope\ScopeResolver $scopes Scopes.
     * @param \CakeDC\OAuth\Server\Grant\ConsentService $consents Consents.
     * @param \CakeDC\OAuth\Server\Grant\CodeIssuer $codes Codes.
     * @param \CakeDC\OAuth\Server\Security\FormToken $formTokens Consent form tokens.
     * @param \CakeDC\OAuth\Server\Http\HttpResponder $responder Responses.
     * @param \CakeDC\OAuth\Server\View\ConsentRendererInterface $consentRenderer Consent page.
     * @param \CakeDC\OAuth\Server\View\ErrorPageRendererInterface $errorRenderer Error page.
     * @param \CakeDC\OAuth\Server\RateLimit\RateLimiter $rateLimiter Rate limiting.
     * @param \Psr\EventDispatcher\EventDispatcherInterface $events Events.
     * @param \Psr\Log\LoggerInterface $logger Logger.
     * @param \Closure $clientIp `fn (ServerRequestInterface $request): string`.
     */
    public function __construct(
        private readonly ServerConfig $config,
        private readonly AuthorizationRequestValidator $validator,
        private readonly UserContextInterface $userContext,
        private readonly UserProviderInterface $users,
        private readonly ScopeResolver $scopes,
        private readonly ConsentService $consents,
        private readonly CodeIssuer $codes,
        private readonly FormToken $formTokens,
        private readonly HttpResponder $responder,
        private readonly ConsentRendererInterface $consentRenderer,
        private readonly ErrorPageRendererInterface $errorRenderer,
        private readonly RateLimiter $rateLimiter,
        private readonly EventDispatcherInterface $events,
        private readonly LoggerInterface $logger,
        private readonly Closure $clientIp,
    ) {
    }

    /**
     * @inheritDoc
     */
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $status = $request->getMethod() === 'POST' ? 303 : 302;
        try {
            $this->rateLimiter->hit('authorize', ($this->clientIp)($request));

            return $this->authorize($request);
        } catch (AuthorizationError $e) {
            if (!$e->isRedirectable()) {
                return $this->errorPage($e->error);
            }

            return $this->responder->redirect(RedirectUrl::build((string)$e->redirectUri, [
                'error' => $e->error->error,
                'error_description' => $e->error->getMessage(),
                'state' => $e->state,
                'iss' => $this->config->issuer,
            ]), $status);
        } catch (OAuthException $e) {
            return $this->errorPage($e);
        } catch (Throwable $e) {
            $this->logger->error('Authorization failed: {message}', ['message' => $e->getMessage(), 'exception' => $e]);

            return $this->errorPage(OAuthException::serverError());
        }
    }

    /**
     * The endpoint logic.
     *
     * @throws \CakeDC\OAuth\Server\Grant\AuthorizationError
     * @throws \CakeDC\OAuth\Server\Exception\OAuthException
     */
    private function authorize(ServerRequestInterface $request): ResponseInterface
    {
        $method = $request->getMethod();
        if ($method !== 'GET' && $method !== 'POST') {
            return $this->responder->methodNotAllowed('GET, POST');
        }
        $path = RequestPath::safe($request);
        if ($method === 'GET') {
            [$params, $repeated] = Params::parse($request->getUri()->getQuery());
        } else {
            [$params, $repeated] = FormBody::read($request);
        }
        // Only repeats of authorization parameters count (RFC 6749 section 3.1).
        $repeated = array_values(array_intersect($repeated, AuthorizationRequest::PARAMETERS));
        $authorization = $this->validator->validate($params, $repeated, ($this->clientIp)($request));
        $owner = $this->userContext->currentOwner($request);
        if ($owner === null) {
            if ($method === 'POST') {
                throw OAuthException::accessDenied('Your session ended. Start again from the application.');
            }

            return $this->userContext->loginResponse($request, $this->returnTo($request, $path));
        }
        if ($owner->type !== SubjectType::User) {
            // A client identity is not a person: nobody is there to consent.
            throw OAuthException::invalidRequest('Only people can authorize applications.');
        }
        $client = $authorization->client;
        $resource = $authorization->resource;
        $fail = fn(OAuthException $error): AuthorizationError => new AuthorizationError(
            $error,
            $authorization->redirectUri,
            $authorization->state,
        );
        // Decide first, act later: a forged POST must not cause events or redirects.
        $allowed = $this->users->canAuthorize($owner, $client, $resource);
        $granted = [];
        $scopeError = null;
        try {
            $granted = $this->scopes->resolve(
                $resource,
                $authorization->scopes,
                $client->scopes,
                $this->users->scopesFor($owner, $resource),
            );
        } catch (OAuthException $e) {
            $scopeError = $e;
        }
        // What the owner is asked to approve, offline_access included.
        $effective = $authorization->offlineAccess ? [...$granted, Scopes::OFFLINE_ACCESS] : $granted;
        $context = 'consent:' . $authorization->fingerprint() . ':' . implode(' ', $effective);
        if ($method === 'POST') {
            $token = $params['consent_token'] ?? '';
            if (!$this->formTokens->verify($token, $context, $owner->subject)) {
                throw OAuthException::invalidRequest(
                    'The consent form expired or was changed. Start again from the application.',
                );
            }
        }
        if (!$allowed) {
            $this->events->dispatch(new AuthorizationDenied($client, $owner, 'not_allowed'));
            throw $fail(OAuthException::accessDenied('You may not authorize this application.'));
        }
        if ($scopeError !== null) {
            throw $fail($scopeError);
        }
        if ($granted === []) {
            throw $fail(OAuthException::invalidScope('None of the requested permissions can be granted.'));
        }
        if ($method === 'GET') {
            if ($this->consents->isGranted($owner, $client, $resource, $effective)) {
                return $this->approve($authorization, $owner, $granted, 302);
            }
            $descriptions = [];
            foreach ($granted as $scope) {
                $descriptions[$scope] = $resource->scopes[$scope];
            }

            return $this->responder->page($this->consentRenderer->render(new ConsentView(
                $client,
                $owner,
                $resource,
                $descriptions,
                $this->config->issuesRefreshTokens($authorization->offlineAccess)
                    && $client->allowsGrant(GrantType::REFRESH_TOKEN),
                $authorization->redirectUri,
                $path,
                $authorization->formFields() + ['consent_token' => $this->formTokens->issue($context, $owner->subject)],
            )));
        }
        if (($params['decision'] ?? '') !== 'approve') {
            $this->events->dispatch(new AuthorizationDenied($client, $owner, 'user_denied'));
            throw $fail(OAuthException::accessDenied('You denied the request.'));
        }
        $this->consents->grant($owner, $client, $resource, $effective);

        return $this->approve($authorization, $owner, $granted, 303);
    }

    /**
     * Issues the code and sends it back.
     *
     * @param list<string> $granted Granted scopes.
     */
    private function approve(
        AuthorizationRequest $authorization,
        ResourceOwner $owner,
        array $granted,
        int $status,
    ): ResponseInterface {
        $code = $this->codes->issue($authorization, $owner, $granted);

        return $this->responder->redirect(RedirectUrl::build($authorization->redirectUri, [
            'code' => $code,
            'state' => $authorization->state,
            'iss' => $this->config->issuer,
        ]), $status);
    }

    /**
     * The relative URL to come back to after the login.
     */
    private function returnTo(ServerRequestInterface $request, string $path): string
    {
        $query = $request->getUri()->getQuery();

        return $path . ($query === '' ? '' : '?' . $query);
    }

    /**
     * The error page for $error.
     */
    private function errorPage(OAuthException $error): ResponseInterface
    {
        $status = $error->status === 401 ? 400 : $error->status;

        return $this->responder->page($this->errorRenderer->render($error), $status, $error->headers);
    }
}
