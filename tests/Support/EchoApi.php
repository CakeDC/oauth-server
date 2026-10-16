<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Support;

use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Token\ValidatedToken;
use Nyholm\Psr7\Response;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * A protected API stub that answers 200 and remembers the owner and scopes the middleware passed in.
 */
final class EchoApi implements RequestHandlerInterface
{
    public ?ResourceOwner $owner = null;

    /**
     * @var list<string>|null
     */
    public ?array $scopes = null;

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $owner = $request->getAttribute(ResourceOwner::class);
        $token = $request->getAttribute(ValidatedToken::class);
        $this->owner = $owner instanceof ResourceOwner ? $owner : null;
        $this->scopes = $token instanceof ValidatedToken ? $token->scopes : null;

        return new Response(200, [], 'tools');
    }
}
