<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Http\Handler;

use CakeDC\OAuth\Server\Config\ServerConfig;
use CakeDC\OAuth\Server\Connections\ConnectionService;
use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Http\FormBody;
use CakeDC\OAuth\Server\Http\HttpResponder;
use CakeDC\OAuth\Server\Http\RequestPath;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Owner\UserContextInterface;
use CakeDC\OAuth\Server\Security\FormToken;
use CakeDC\OAuth\Server\View\ConnectionsRendererInterface;
use CakeDC\OAuth\Server\View\ConnectionsView;
use CakeDC\OAuth\Server\View\ErrorPageRendererInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * The page where a signed-in person sees and revokes connections and personal tokens.
 */
final class ConnectionsHandler implements RequestHandlerInterface
{
    private const CONTEXT = 'connections';

    /**
     * @param \CakeDC\OAuth\Server\Config\ServerConfig $config Settings.
     * @param \CakeDC\OAuth\Server\Connections\ConnectionService $connections Connections.
     * @param \CakeDC\OAuth\Server\Owner\UserContextInterface $userContext The signed-in person.
     * @param \CakeDC\OAuth\Server\Security\FormToken $formTokens Form tokens.
     * @param \CakeDC\OAuth\Server\Http\HttpResponder $responder Responses.
     * @param \CakeDC\OAuth\Server\View\ConnectionsRendererInterface $renderer The page.
     * @param \CakeDC\OAuth\Server\View\ErrorPageRendererInterface $errorRenderer Error page.
     * @param \Psr\Log\LoggerInterface $logger Logger.
     */
    public function __construct(
        private readonly ServerConfig $config,
        private readonly ConnectionService $connections,
        private readonly UserContextInterface $userContext,
        private readonly FormToken $formTokens,
        private readonly HttpResponder $responder,
        private readonly ConnectionsRendererInterface $renderer,
        private readonly ErrorPageRendererInterface $errorRenderer,
        private readonly LoggerInterface $logger,
    ) {
    }

    /**
     * @inheritDoc
     */
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        try {
            if (!$this->config->connections) {
                return $this->error(new OAuthException('not_found', 'The connections page is disabled.', 404));
            }
            $owner = $this->userContext->currentOwner($request);
            if ($owner === null) {
                $query = $request->getUri()->getQuery();

                return $this->userContext->loginResponse(
                    $request,
                    RequestPath::safe($request) . ($query === '' ? '' : '?' . $query),
                );
            }
            if ($request->getMethod() === 'GET') {
                return $this->responder->page($this->renderer->render($this->view($owner, $request)));
            }
            if ($request->getMethod() !== 'POST') {
                return $this->responder->methodNotAllowed('GET, POST');
            }

            return $this->act($owner, $request);
        } catch (Throwable $e) {
            if ($e instanceof OAuthException) {
                return $this->error($e);
            }
            $this->logger->error('Connections page failed: {message}', [
                'message' => $e->getMessage(),
                'exception' => $e,
            ]);

            return $this->error(OAuthException::serverError());
        }
    }

    /**
     * Runs a posted action.
     */
    private function act(ResourceOwner $owner, ServerRequestInterface $request): ResponseInterface
    {
        [$params] = FormBody::read($request);
        if (!$this->formTokens->verify($params['form_token'] ?? '', self::CONTEXT, $owner->subject)) {
            return $this->error(OAuthException::invalidRequest('The form expired. Reload the page and try again.'));
        }
        $action = $params['action'] ?? '';
        $personal = in_array($action, ['create_token', 'revoke_token'], true);
        if ($personal && !$this->config->personalTokens) {
            return $this->error(OAuthException::invalidRequest('Personal access tokens are disabled.'));
        }
        $back = $this->responder->redirect(RequestPath::safe($request), 303);
        switch ($action) {
            case 'revoke_connection':
                $this->connections->revokeConnection($owner, $params['family_id'] ?? '');

                return $back;
            case 'revoke_token':
                $this->connections->revokePersonalToken($owner, $params['token_id'] ?? '');

                return $back;
            case 'create_token':
                $scopes = [];
                foreach ($params as $name => $value) {
                    if (str_starts_with($name, 'scope:') && $value === '1') {
                        $scopes[] = substr($name, 6);
                    }
                }
                try {
                    $created = $this->connections->createPersonalToken(
                        $owner,
                        $params['name'] ?? '',
                        $params['resource'] ?? '',
                        $scopes,
                        (int)($params['days'] ?? 0),
                    );
                } catch (OAuthException $e) {
                    return $this->responder->page(
                        $this->renderer->render($this->view($owner, $request, null, $e->getMessage())),
                        422,
                    );
                }

                return $this->responder->page(
                    $this->renderer->render($this->view($owner, $request, $created['value'])),
                );
            default:
                return $this->error(OAuthException::invalidRequest('Unknown action.'));
        }
    }

    /**
     * The page model.
     */
    private function view(
        ResourceOwner $owner,
        ServerRequestInterface $request,
        ?string $newToken = null,
        ?string $error = null,
    ): ConnectionsView {
        $names = [];
        foreach ($this->config->resources->all() as $resource) {
            $names[$resource->identifier] = $resource->name;
        }

        return new ConnectionsView(
            $owner,
            $this->connections->connections($owner),
            $this->config->personalTokens ? $this->connections->personalTokens($owner) : [],
            $this->config->personalTokens ? $this->connections->creatableScopes($owner) : [],
            $names,
            RequestPath::safe($request),
            $this->formTokens->issue(self::CONTEXT, $owner->subject),
            $this->connections->maxPersonalDays(),
            $this->config->personalTokens,
            $newToken,
            $error,
        );
    }

    /**
     * The error page.
     */
    private function error(OAuthException $error): ResponseInterface
    {
        return $this->responder->page($this->errorRenderer->render($error), $error->status);
    }
}
