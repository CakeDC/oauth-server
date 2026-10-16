<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Http\Handler;

use CakeDC\OAuth\Server\Client\ClientAuthenticator;
use CakeDC\OAuth\Server\Client\GrantType;
use CakeDC\OAuth\Server\Config\ServerConfig;
use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Grant\Pkce;
use CakeDC\OAuth\Server\Http\FormBody;
use CakeDC\OAuth\Server\Http\HttpResponder;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Owner\UserProviderInterface;
use CakeDC\OAuth\Server\RateLimit\RateLimiter;
use CakeDC\OAuth\Server\Scope\ScopeResolver;
use CakeDC\OAuth\Server\Scope\Scopes;
use CakeDC\OAuth\Server\Storage\AuthorizationCodeRepositoryInterface;
use CakeDC\OAuth\Server\Storage\ClientRepositoryInterface;
use CakeDC\OAuth\Server\Support\Uuid;
use CakeDC\OAuth\Server\Token\IssuedTokens;
use CakeDC\OAuth\Server\Token\RefreshTokenRotator;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use CakeDC\OAuth\Server\Token\TokenIssuer;
use CakeDC\OAuth\Server\Token\TokenRevoker;
use Closure;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * The token endpoint: authorization code, refresh token and client credentials grants.
 *
 * @internal Built through the AuthorizationServer factories, not by you: get it from the server.
 * Its constructor may change in any 1.x release.
 */
final class TokenHandler implements RequestHandlerInterface
{
    use GuardsErrors;

    /**
     * @param \CakeDC\OAuth\Server\Config\ServerConfig $config Settings.
     * @param \CakeDC\OAuth\Server\Client\ClientAuthenticator $clientAuthenticator Client authentication.
     * @param \CakeDC\OAuth\Server\Storage\AuthorizationCodeRepositoryInterface $codes Codes.
     * @param \CakeDC\OAuth\Server\Storage\ClientRepositoryInterface $clients Clients.
     * @param \CakeDC\OAuth\Server\Owner\UserProviderInterface $users People.
     * @param \CakeDC\OAuth\Server\Scope\ScopeResolver $scopes Scopes.
     * @param \CakeDC\OAuth\Server\Token\TokenIssuer $issuer Issuer.
     * @param \CakeDC\OAuth\Server\Token\RefreshTokenRotator $rotator Refresh rotation.
     * @param \CakeDC\OAuth\Server\Token\TokenRevoker $revoker Revoker.
     * @param \CakeDC\OAuth\Server\RateLimit\RateLimiter $rateLimiter Rate limiting.
     * @param \CakeDC\OAuth\Server\Http\HttpResponder $responder Responses.
     * @param \Psr\Clock\ClockInterface $clock Clock.
     * @param \Psr\Log\LoggerInterface $logger Logger.
     * @param \Closure $clientIp `fn (ServerRequestInterface $request): string`.
     */
    public function __construct(
        private readonly ServerConfig $config,
        private readonly ClientAuthenticator $clientAuthenticator,
        private readonly AuthorizationCodeRepositoryInterface $codes,
        private readonly ClientRepositoryInterface $clients,
        private readonly UserProviderInterface $users,
        private readonly ScopeResolver $scopes,
        private readonly TokenIssuer $issuer,
        private readonly RefreshTokenRotator $rotator,
        private readonly TokenRevoker $revoker,
        private readonly RateLimiter $rateLimiter,
        private readonly HttpResponder $responder,
        private readonly ClockInterface $clock,
        private readonly LoggerInterface $logger,
        private readonly Closure $clientIp,
    ) {
    }

    /**
     * @inheritDoc
     */
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        if ($request->getMethod() === 'OPTIONS') {
            return $this->responder->preflight();
        }

        return $this->guarded(function () use ($request): ResponseInterface {
            if ($request->getMethod() !== 'POST') {
                return $this->responder->methodNotAllowed('POST, OPTIONS');
            }
            $this->rateLimiter->hit('token', ($this->clientIp)($request));
            if (!FormBody::isForm($request)) {
                throw OAuthException::invalidRequest(
                    'Send the parameters form-encoded (application/x-www-form-urlencoded).',
                );
            }
            [$body, $repeated] = FormBody::read($request);
            if ($repeated !== []) {
                throw OAuthException::invalidRequest(sprintf('"%s" was sent more than once.', $repeated[0]));
            }
            $grantType = $body['grant_type'] ?? '';
            $issued = match ($grantType) {
                GrantType::AUTHORIZATION_CODE => $this->authorizationCode($request, $body),
                GrantType::REFRESH_TOKEN => $this->refreshToken($request, $body),
                GrantType::CLIENT_CREDENTIALS => $this->clientCredentials($request, $body),
                '' => throw OAuthException::invalidRequest('"grant_type" is missing.'),
                default => throw OAuthException::unsupportedGrantType(
                    sprintf('The grant type "%s" is not supported.', $grantType),
                ),
            };

            return $this->responder->json($issued->toResponse());
        });
    }

    /**
     * The authorization code grant.
     *
     * @param array<string, string> $body Form parameters.
     * @throws \CakeDC\OAuth\Server\Exception\OAuthException
     */
    private function authorizationCode(ServerRequestInterface $request, array $body): IssuedTokens
    {
        $client = $this->clientAuthenticator->authenticate($request, $body, ($this->clientIp)($request));
        if (!$client->allowsGrant(GrantType::AUTHORIZATION_CODE)) {
            throw OAuthException::unauthorizedClient('This client may not use the authorization code grant.');
        }
        $value = $body['code'] ?? '';
        if ($value === '') {
            throw OAuthException::invalidRequest('"code" is missing.');
        }
        $now = $this->clock->now();
        $code = $this->codes->findCodeByHash(TokenGenerator::hash($value));
        if ($code === null || $code->clientInternalId !== $client->id) {
            throw OAuthException::invalidGrant('The authorization code is invalid.');
        }
        // The verifier is checked before reacting to a used code, so that only the holder of the
        // code and its verifier can make a replay revoke anything.
        $verifier = $body['code_verifier'] ?? '';
        if ($verifier === '') {
            throw OAuthException::invalidRequest('"code_verifier" is missing.');
        }
        if (!Pkce::verify($verifier, $code->codeChallenge)) {
            throw OAuthException::invalidGrant('The code_verifier does not match.');
        }
        if ($code->usedAt !== null) {
            if ($code->familyId !== null) {
                $this->revoker->revokeFamily($code->familyId, 'code_reuse');
            }
            throw OAuthException::invalidGrant('The authorization code was already used.');
        }
        if ($code->isExpired($now)) {
            throw OAuthException::invalidGrant('The authorization code expired.');
        }
        $redirectUri = $body['redirect_uri'] ?? '';
        if ($redirectUri === '' && count($client->redirectUris) > 1) {
            throw OAuthException::invalidRequest('"redirect_uri" is missing.');
        }
        if ($redirectUri !== '' && $redirectUri !== $code->redirectUri) {
            throw OAuthException::invalidGrant('redirect_uri does not match the authorization request.');
        }
        $resource = $this->config->resources->get($code->resource);
        if ($resource === null) {
            throw OAuthException::invalidGrant('The resource of this code no longer exists.');
        }
        $requestedResource = $body['resource'] ?? '';
        if (
            $requestedResource !== ''
            && $this->config->resources->get($requestedResource)?->identifier !== $resource->identifier
        ) {
            throw OAuthException::invalidTarget('The code was issued for another resource.');
        }
        $owner = $this->users->findBySubject($code->subject);
        if ($owner === null) {
            throw OAuthException::invalidGrant('The person who approved this code no longer has access.');
        }
        // What the person may hold now, not what they could at /authorize. Nothing left: the code is not consumed.
        $scopes = $this->scopes->withinOwnerAllowance(
            $resource,
            array_values(array_filter(
                array_diff($code->scopes, [Scopes::OFFLINE_ACCESS]),
                fn(string $scope): bool => $resource->hasScope($scope),
            )),
            $this->users->scopesFor($owner, $resource),
        );
        if ($scopes === []) {
            throw OAuthException::invalidGrant('The grant no longer allows any scope.');
        }
        // Issue first, consume second: any family recorded on a used code already has its tokens,
        // so a concurrent replay can always revoke them.
        $familyId = Uuid::v4();
        $offlineAccess = in_array(Scopes::OFFLINE_ACCESS, $code->scopes, true);
        try {
            $issued = $this->issuer->issue(
                $client,
                $code->subject,
                SubjectType::User,
                $resource,
                $scopes,
                $familyId,
                $this->config->issuesRefreshTokens($offlineAccess) && $client->allowsGrant(GrantType::REFRESH_TOKEN),
            );
        } catch (Throwable $e) {
            // Whatever was saved before the failure must not stay live.
            $this->revoker->revokeFamily($familyId, 'issue_failed');

            throw $e;
        }
        if (!$this->codes->consumeCode($code->id, $now, $familyId)) {
            $this->revoker->revokeFamily($familyId, 'code_reuse');
            $winner = $this->codes->findCodeByHash($code->codeHash);
            if ($winner?->familyId !== null && $winner->familyId !== $familyId) {
                $this->revoker->revokeFamily($winner->familyId, 'code_reuse');
            }
            throw OAuthException::invalidGrant('The authorization code was already used.');
        }
        $this->touch($client->id, $now);

        return $issued;
    }

    /**
     * The refresh token grant.
     *
     * @param array<string, string> $body Form parameters.
     * @throws \CakeDC\OAuth\Server\Exception\OAuthException
     */
    private function refreshToken(ServerRequestInterface $request, array $body): IssuedTokens
    {
        $client = $this->clientAuthenticator->authenticate($request, $body, ($this->clientIp)($request));
        if (!$client->allowsGrant(GrantType::REFRESH_TOKEN)) {
            throw OAuthException::unauthorizedClient('This client may not use refresh tokens.');
        }
        $value = $body['refresh_token'] ?? '';
        if ($value === '') {
            throw OAuthException::invalidRequest('"refresh_token" is missing.');
        }
        $requested = array_values(array_diff(Scopes::parse($body['scope'] ?? null), [Scopes::OFFLINE_ACCESS]));
        $issued = $this->rotator->rotate($client, $value, $body['resource'] ?? null, $requested);
        $this->touch($client->id, $this->clock->now());

        return $issued;
    }

    /**
     * The client credentials grant.
     *
     * @param array<string, string> $body Form parameters.
     * @throws \CakeDC\OAuth\Server\Exception\OAuthException
     */
    private function clientCredentials(ServerRequestInterface $request, array $body): IssuedTokens
    {
        if (!$this->config->clientCredentials) {
            throw OAuthException::unsupportedGrantType('The client credentials grant is disabled.');
        }
        $client = $this->clientAuthenticator->authenticate($request, $body, ($this->clientIp)($request));
        if ($client->isPublic() || !$client->allowsGrant(GrantType::CLIENT_CREDENTIALS)) {
            throw OAuthException::unauthorizedClient('This client may not use client credentials.');
        }
        $resourceParam = $body['resource'] ?? '';
        $resource = $resourceParam === ''
            ? $this->config->resources->defaultResource()
            : $this->config->resources->get($resourceParam);
        if ($resource === null) {
            throw OAuthException::invalidTarget('The requested resource is unknown.');
        }
        $owner = $this->users->forClient($client, $resource);
        if ($owner === null) {
            throw OAuthException::unauthorizedClient('No identity is configured for this client.');
        }
        $requested = array_values(array_diff(Scopes::parse($body['scope'] ?? null), [Scopes::OFFLINE_ACCESS]));
        $granted = $this->scopes->resolve(
            $resource,
            $requested,
            $client->scopes,
            $this->users->scopesFor($owner, $resource),
        );
        if ($granted === []) {
            throw OAuthException::invalidScope('None of the requested scopes can be granted.');
        }
        $issued = $this->issuer->issue(
            $client,
            $client->clientId,
            SubjectType::Client,
            $resource,
            $granted,
            Uuid::v4(),
            false,
        );
        $this->touch($client->id, $this->clock->now());

        return $issued;
    }

    /**
     * Records the client's last use. A failure is logged and ignored: the grant already happened.
     */
    private function touch(string $clientId, DateTimeImmutable $at): void
    {
        try {
            $this->clients->touchClient($clientId, $at);
        } catch (Throwable $e) {
            $this->logger->error('Could not record client use: {message}', ['message' => $e->getMessage()]);
        }
    }
}
