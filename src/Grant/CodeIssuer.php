<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Grant;

use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Scope\Scopes;
use CakeDC\OAuth\Server\Storage\AuthorizationCodeRepositoryInterface;
use CakeDC\OAuth\Server\Support\Time;
use CakeDC\OAuth\Server\Support\Uuid;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use Psr\Clock\ClockInterface;

/**
 * Issues authorization codes.
 *
 * @internal Built through the AuthorizationServer factories, not by you: get it from the server.
 * Its constructor may change in any 1.x release.
 */
final class CodeIssuer
{
    /**
     * @param \CakeDC\OAuth\Server\Storage\AuthorizationCodeRepositoryInterface $codes Storage.
     * @param \CakeDC\OAuth\Server\Token\TokenGenerator $generator Secrets.
     * @param \Psr\Clock\ClockInterface $clock Clock.
     * @param int $lifetime Seconds a code stays valid.
     */
    public function __construct(
        private readonly AuthorizationCodeRepositoryInterface $codes,
        private readonly TokenGenerator $generator,
        private readonly ClockInterface $clock,
        private readonly int $lifetime = 60,
    ) {
    }

    /**
     * Stores a code for an approved request and returns it.
     *
     * @param \CakeDC\OAuth\Server\Grant\AuthorizationRequest $request The request.
     * @param \CakeDC\OAuth\Server\Owner\ResourceOwner $owner Who approved.
     * @param list<string> $scopes Granted scopes.
     */
    public function issue(AuthorizationRequest $request, ResourceOwner $owner, array $scopes): string
    {
        $code = $this->generator->authorizationCode();
        $now = $this->clock->now();
        $this->codes->saveCode(new AuthorizationCode(
            id: Uuid::v4(),
            codeHash: TokenGenerator::hash($code),
            clientInternalId: $request->client->id,
            subject: $owner->subject,
            redirectUri: $request->redirectUri,
            resource: $request->resource->identifier,
            scopes: array_values(array_unique(
                $request->offlineAccess ? [...$scopes, Scopes::OFFLINE_ACCESS] : $scopes,
            )),
            codeChallenge: $request->codeChallenge,
            expiresAt: Time::plus($now, $this->lifetime),
            createdAt: $now,
        ));

        return $code;
    }
}
