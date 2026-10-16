<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Owner;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The signed-in person of a browser request. Implemented by the application, which owns login.
 */
interface UserContextInterface
{
    /**
     * The signed-in owner of $request, or null.
     */
    public function currentOwner(ServerRequestInterface $request): ?ResourceOwner;

    /**
     * The response that sends an anonymous visitor to the login, coming back to $returnTo afterwards.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @param string $returnTo A relative URL (path and query) on this application.
     */
    public function loginResponse(ServerRequestInterface $request, string $returnTo): ResponseInterface;
}
