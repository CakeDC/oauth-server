<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server;

use CakeDC\OAuth\Server\Bridge\McpSdk\TokenValidator as McpTokenValidator;
use CakeDC\OAuth\Server\Client\Cimd\CurlTransport;
use CakeDC\OAuth\Server\Client\Cimd\DnsResolverInterface;
use CakeDC\OAuth\Server\Client\Cimd\HttpTransportInterface;
use CakeDC\OAuth\Server\Client\Cimd\MetadataDocumentFetcher;
use CakeDC\OAuth\Server\Client\Cimd\SystemDnsResolver;
use CakeDC\OAuth\Server\Client\ClientAuthenticator;
use CakeDC\OAuth\Server\Client\ClientRegistrar;
use CakeDC\OAuth\Server\Client\ClientResolver;
use CakeDC\OAuth\Server\Clock\SystemClock;
use CakeDC\OAuth\Server\Config\ServerConfig;
use CakeDC\OAuth\Server\Connections\ConnectionService;
use CakeDC\OAuth\Server\Event\NullEventDispatcher;
use CakeDC\OAuth\Server\Grant\AuthorizationRequestValidator;
use CakeDC\OAuth\Server\Grant\CodeIssuer;
use CakeDC\OAuth\Server\Grant\ConsentService;
use CakeDC\OAuth\Server\Http\ClientIp;
use CakeDC\OAuth\Server\Http\Handler\AuthorizationServerMetadataHandler;
use CakeDC\OAuth\Server\Http\Handler\AuthorizeHandler;
use CakeDC\OAuth\Server\Http\Handler\ConnectionsHandler;
use CakeDC\OAuth\Server\Http\Handler\IntrospectHandler;
use CakeDC\OAuth\Server\Http\Handler\RegisterHandler;
use CakeDC\OAuth\Server\Http\Handler\RevokeHandler;
use CakeDC\OAuth\Server\Http\Handler\TokenHandler;
use CakeDC\OAuth\Server\Http\HttpResponder;
use CakeDC\OAuth\Server\Http\Middleware\BearerTokenMiddleware;
use CakeDC\OAuth\Server\Maintenance\Pruner;
use CakeDC\OAuth\Server\Owner\UserContextInterface;
use CakeDC\OAuth\Server\Owner\UserProviderInterface;
use CakeDC\OAuth\Server\RateLimit\RateLimiter;
use CakeDC\OAuth\Server\Scope\ScopeResolver;
use CakeDC\OAuth\Server\Security\FormToken;
use CakeDC\OAuth\Server\Storage\StorageInterface;
use CakeDC\OAuth\Server\Token\RefreshTokenRotator;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use CakeDC\OAuth\Server\Token\TokenIssuer;
use CakeDC\OAuth\Server\Token\TokenRevoker;
use CakeDC\OAuth\Server\Token\TokenValidator;
use CakeDC\OAuth\Server\View\ConnectionsRendererInterface;
use CakeDC\OAuth\Server\View\ConsentRendererInterface;
use CakeDC\OAuth\Server\View\ErrorPageRendererInterface;
use CakeDC\OAuth\Server\View\Html\HtmlConnectionsRenderer;
use CakeDC\OAuth\Server\View\Html\HtmlConsentRenderer;
use CakeDC\OAuth\Server\View\Html\HtmlErrorPageRenderer;
use CakeDC\OAuth\Server\View\Messages;
use Closure;
use InvalidArgumentException;
use LogicException;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Psr\SimpleCache\CacheInterface;

/**
 * Builds the server: every service once, and one PSR-15 handler per endpoint.
 */
final class AuthorizationServer
{
    private EventDispatcherInterface $events;

    private ClockInterface $clock;

    private LoggerInterface $logger;

    private HttpResponder $responder;

    private Messages $messages;

    private Closure $clientIp;

    private ?MetadataDocumentFetcher $fetcher = null;

    private ?TokenGenerator $tokenGenerator = null;

    private ?ScopeResolver $scopeResolver = null;

    private ?ClientResolver $clientResolver = null;

    private ?ClientAuthenticator $clientAuthenticator = null;

    private ?ClientRegistrar $clientRegistrar = null;

    private ?AuthorizationRequestValidator $requestValidator = null;

    private ?ConsentService $consentService = null;

    private ?CodeIssuer $codeIssuer = null;

    private ?TokenIssuer $tokenIssuer = null;

    private ?TokenRevoker $tokenRevoker = null;

    private ?RefreshTokenRotator $refreshTokenRotator = null;

    private ?TokenValidator $tokenValidator = null;

    private ?ConnectionService $connectionService = null;

    private ?FormToken $formToken = null;

    private ?RateLimiter $rateLimiter = null;

    /**
     * @param \CakeDC\OAuth\Server\Config\ServerConfig $config Settings.
     * @param \CakeDC\OAuth\Server\Storage\StorageInterface $storage Storage.
     * @param \CakeDC\OAuth\Server\Owner\UserProviderInterface $users The application's people.
     * @param \CakeDC\OAuth\Server\Owner\UserContextInterface $userContext The signed-in person.
     * @param \Psr\Http\Message\ResponseFactoryInterface $responseFactory PSR-17.
     * @param \Psr\Http\Message\StreamFactoryInterface $streamFactory PSR-17.
     * @param \Psr\EventDispatcher\EventDispatcherInterface|null $events Events; dropped by default.
     * @param \Psr\SimpleCache\CacheInterface|null $cache For rate limiting; null disables it.
     * @param \Psr\Clock\ClockInterface|null $clock Clock.
     * @param \Psr\Log\LoggerInterface|null $logger Logger.
     * @param \CakeDC\OAuth\Server\Client\Cimd\HttpTransportInterface|null $transport Metadata document fetching.
     * @param \CakeDC\OAuth\Server\Client\Cimd\DnsResolverInterface|null $dns DNS.
     * @param \CakeDC\OAuth\Server\View\Messages|null $messages Texts of the built-in pages.
     * @param \CakeDC\OAuth\Server\View\ConsentRendererInterface|null $consentRenderer Consent page.
     * @param \CakeDC\OAuth\Server\View\ConnectionsRendererInterface|null $connectionsRenderer Connections page.
     * @param \CakeDC\OAuth\Server\View\ErrorPageRendererInterface|null $errorPageRenderer Error page.
     * @param \Closure|null $clientIp `fn (ServerRequestInterface $request): string`, for rate limiting.
     * @throws \LogicException When metadata documents are enabled without ext-curl or a transport.
     */
    public function __construct(
        private readonly ServerConfig $config,
        private readonly StorageInterface $storage,
        private readonly UserProviderInterface $users,
        private readonly UserContextInterface $userContext,
        ResponseFactoryInterface $responseFactory,
        StreamFactoryInterface $streamFactory,
        ?EventDispatcherInterface $events = null,
        private readonly ?CacheInterface $cache = null,
        ?ClockInterface $clock = null,
        ?LoggerInterface $logger = null,
        ?HttpTransportInterface $transport = null,
        ?DnsResolverInterface $dns = null,
        ?Messages $messages = null,
        private readonly ?ConsentRendererInterface $consentRenderer = null,
        private readonly ?ConnectionsRendererInterface $connectionsRenderer = null,
        private readonly ?ErrorPageRendererInterface $errorPageRenderer = null,
        ?Closure $clientIp = null,
    ) {
        $this->events = $events ?? new NullEventDispatcher();
        $this->clock = $clock ?? new SystemClock();
        $this->logger = $logger ?? new NullLogger();
        $this->responder = new HttpResponder($responseFactory, $streamFactory);
        $this->messages = $messages ?? new Messages();
        $this->clientIp = $clientIp ?? ClientIp::fromServerParams(...);
        if ($config->cimdEnabled) {
            if ($transport === null && !extension_loaded('curl')) {
                throw new LogicException(
                    'Client ID Metadata Documents need ext-curl or a transport; or set "cimd.enabled" to false.',
                );
            }
            $this->fetcher = new MetadataDocumentFetcher(
                $dns ?? new SystemDnsResolver(),
                $transport ?? new CurlTransport(),
                $config->cimdTimeout,
                $config->cimdMaxBytes,
                $config->cimdAllowedHosts,
            );
        }
    }

    /**
     * The settings.
     */
    public function config(): ServerConfig
    {
        return $this->config;
    }

    /**
     * The storage.
     */
    public function storage(): StorageInterface
    {
        return $this->storage;
    }

    /**
     * The clock.
     */
    public function clock(): ClockInterface
    {
        return $this->clock;
    }

    /**
     * The response builder.
     */
    public function responder(): HttpResponder
    {
        return $this->responder;
    }

    /**
     * Ids, tokens and secrets.
     */
    public function tokenGenerator(): TokenGenerator
    {
        return $this->tokenGenerator ??= new TokenGenerator($this->config->tokenPrefix);
    }

    /**
     * Scope decisions.
     */
    public function scopeResolver(): ScopeResolver
    {
        return $this->scopeResolver ??= new ScopeResolver();
    }

    /**
     * Client lookup, metadata documents included.
     */
    public function clientResolver(): ClientResolver
    {
        return $this->clientResolver ??= new ClientResolver(
            $this->storage,
            $this->clock,
            $this->fetcher,
            $this->config->cimdCacheMin,
            $this->config->cimdCacheMax,
            $this->config->allowPrivateSchemes,
        );
    }

    /**
     * Client authentication at the token, revocation and introspection endpoints.
     */
    public function clientAuthenticator(): ClientAuthenticator
    {
        return $this->clientAuthenticator ??= new ClientAuthenticator($this->clientResolver());
    }

    /**
     * Client registration, dynamic and by hand.
     */
    public function clientRegistrar(): ClientRegistrar
    {
        return $this->clientRegistrar ??= new ClientRegistrar(
            $this->storage,
            $this->tokenGenerator(),
            $this->clock,
            $this->config->resources,
            $this->events,
            $this->config->allowPrivateSchemes,
        );
    }

    /**
     * Authorization request validation.
     */
    public function authorizationRequestValidator(): AuthorizationRequestValidator
    {
        return $this->requestValidator ??= new AuthorizationRequestValidator(
            $this->clientResolver(),
            $this->config->resources,
        );
    }

    /**
     * Remembered consent.
     */
    public function consentService(): ConsentService
    {
        return $this->consentService ??= new ConsentService($this->storage, $this->clock, $this->events);
    }

    /**
     * Authorization codes.
     */
    public function codeIssuer(): CodeIssuer
    {
        return $this->codeIssuer ??= new CodeIssuer(
            $this->storage,
            $this->tokenGenerator(),
            $this->clock,
            $this->config->lifetimes->code,
        );
    }

    /**
     * Token issuing.
     */
    public function tokenIssuer(): TokenIssuer
    {
        return $this->tokenIssuer ??= new TokenIssuer(
            $this->storage,
            $this->tokenGenerator(),
            $this->clock,
            $this->events,
            $this->config->lifetimes,
        );
    }

    /**
     * Token revocation, for example after a password change.
     */
    public function tokenRevoker(): TokenRevoker
    {
        return $this->tokenRevoker ??= new TokenRevoker($this->storage, $this->clock, $this->events);
    }

    /**
     * Refresh token rotation.
     */
    public function refreshTokenRotator(): RefreshTokenRotator
    {
        return $this->refreshTokenRotator ??= new RefreshTokenRotator(
            $this->storage,
            $this->tokenIssuer(),
            $this->tokenRevoker(),
            $this->scopeResolver(),
            $this->config->resources,
            $this->clock,
            $this->events,
            $this->users,
            $this->config->lifetimes->refreshReuseGrace,
        );
    }

    /**
     * Validation of presented tokens, for resource servers.
     */
    public function tokenValidator(): TokenValidator
    {
        return $this->tokenValidator ??= new TokenValidator(
            $this->storage,
            $this->storage,
            $this->users,
            $this->config->resources,
            $this->scopeResolver(),
            $this->clock,
            personalTokens: $this->config->personalTokens,
        );
    }

    /**
     * Connections and personal tokens.
     */
    public function connectionService(): ConnectionService
    {
        return $this->connectionService ??= new ConnectionService(
            $this->storage,
            $this->storage,
            $this->storage,
            $this->tokenIssuer(),
            $this->tokenRevoker(),
            $this->config->resources,
            $this->users,
            $this->clock,
            $this->config->lifetimes->personalMax,
        );
    }

    /**
     * Housekeeping.
     */
    public function pruner(): Pruner
    {
        return new Pruner($this->storage, $this->clock, $this->config->retentionDays);
    }

    /**
     * Signed form tokens.
     */
    public function formToken(): FormToken
    {
        return $this->formToken ??= new FormToken($this->config->secret, $this->clock);
    }

    /**
     * Rate limiting.
     */
    public function rateLimiter(): RateLimiter
    {
        return $this->rateLimiter ??= new RateLimiter($this->cache, $this->clock, $this->config->rateLimits);
    }

    /**
     * GET {metadataPath}: authorization server metadata.
     */
    public function metadataHandler(): AuthorizationServerMetadataHandler
    {
        return new AuthorizationServerMetadataHandler($this->config, $this->responder);
    }

    /**
     * The error page renderer.
     */
    public function errorPageRenderer(): ErrorPageRendererInterface
    {
        return $this->errorPageRenderer ?? new HtmlErrorPageRenderer($this->messages);
    }

    /**
     * GET and POST {routePrefix}/authorize: the authorization endpoint.
     */
    public function authorizeHandler(): AuthorizeHandler
    {
        return new AuthorizeHandler(
            $this->config,
            $this->authorizationRequestValidator(),
            $this->userContext,
            $this->users,
            $this->scopeResolver(),
            $this->consentService(),
            $this->codeIssuer(),
            $this->formToken(),
            $this->responder,
            $this->consentRenderer ?? new HtmlConsentRenderer($this->messages),
            $this->errorPageRenderer(),
            $this->rateLimiter(),
            $this->events,
            $this->logger,
            $this->clientIp,
        );
    }

    /**
     * POST {routePrefix}/token: the token endpoint.
     */
    public function tokenHandler(): TokenHandler
    {
        return new TokenHandler(
            $this->config,
            $this->clientAuthenticator(),
            $this->storage,
            $this->storage,
            $this->users,
            $this->scopeResolver(),
            $this->tokenIssuer(),
            $this->refreshTokenRotator(),
            $this->tokenRevoker(),
            $this->rateLimiter(),
            $this->responder,
            $this->clock,
            $this->logger,
            $this->clientIp,
        );
    }

    /**
     * POST {routePrefix}/register: dynamic client registration.
     */
    public function registerHandler(): RegisterHandler
    {
        return new RegisterHandler(
            $this->config,
            $this->clientRegistrar(),
            $this->rateLimiter(),
            $this->responder,
            $this->logger,
            $this->clientIp,
        );
    }

    /**
     * POST {routePrefix}/revoke: token revocation.
     */
    public function revokeHandler(): RevokeHandler
    {
        return new RevokeHandler(
            $this->clientAuthenticator(),
            $this->tokenRevoker(),
            $this->rateLimiter(),
            $this->responder,
            $this->logger,
            $this->clientIp,
        );
    }

    /**
     * POST {routePrefix}/introspect: token introspection.
     */
    public function introspectHandler(): IntrospectHandler
    {
        return new IntrospectHandler(
            $this->config,
            $this->clientAuthenticator(),
            $this->storage,
            $this->storage,
            $this->tokenValidator(),
            $this->rateLimiter(),
            $this->responder,
            $this->clock,
            $this->logger,
            $this->clientIp,
            $this->users,
        );
    }

    /**
     * Middleware that protects a PSR-15 route belonging to $resource.
     *
     * @param string $resource Resource identifier.
     * @param string|null $resourceMetadataUrl Protected resource metadata URL named in challenges.
     * @param list<string> $requiredScopes Scopes every request needs.
     * @throws \InvalidArgumentException When the resource is not declared.
     */
    public function bearerMiddleware(
        string $resource,
        ?string $resourceMetadataUrl = null,
        array $requiredScopes = [],
    ): BearerTokenMiddleware {
        $this->assertResource($resource, $requiredScopes);

        return new BearerTokenMiddleware(
            $this->tokenValidator(),
            $this->responder,
            $resource,
            $resourceMetadataUrl,
            $requiredScopes,
        );
    }

    /**
     * The validator for the MCP SDK's AuthorizationMiddleware (requires mcp/sdk).
     *
     * @param string $resource Resource identifier.
     * @throws \InvalidArgumentException When the resource is not declared.
     * @throws \LogicException When mcp/sdk is not installed.
     */
    public function mcpTokenValidator(string $resource): McpTokenValidator
    {
        if (!interface_exists('Mcp\\Server\\Transport\\Http\\OAuth\\AuthorizationTokenValidatorInterface')) {
            throw new LogicException('The MCP SDK bridge requires mcp/sdk.');
        }
        $this->assertResource($resource);

        return new McpTokenValidator($this->tokenValidator(), $resource);
    }

    /**
     * Fails fast on a resource or scopes the configuration does not declare.
     *
     * @param list<string> $scopes Scopes the resource must declare.
     */
    private function assertResource(string $resource, array $scopes = []): void
    {
        $declared = $this->config->resources->get($resource);
        if ($declared === null) {
            throw new InvalidArgumentException(sprintf('Resource "%s" is not declared.', $resource));
        }
        foreach ($scopes as $scope) {
            if (!$declared->hasScope($scope)) {
                throw new InvalidArgumentException(
                    sprintf('Scope "%s" is not declared by the resource "%s".', $scope, $resource),
                );
            }
        }
    }

    /**
     * GET and POST {routePrefix}/connections: the connections page.
     */
    public function connectionsHandler(): ConnectionsHandler
    {
        return new ConnectionsHandler(
            $this->config,
            $this->connectionService(),
            $this->userContext,
            $this->formToken(),
            $this->responder,
            $this->connectionsRenderer ?? new HtmlConnectionsRenderer($this->messages),
            $this->errorPageRenderer(),
            $this->logger,
        );
    }
}
