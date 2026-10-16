<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Support;

use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Owner\UserContextInterface;
use Nyholm\Psr7\Response;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class FakeUserContext implements UserContextInterface
{
    public ?ResourceOwner $owner = null;

    public ?string $returnTo = null;

    public function currentOwner(ServerRequestInterface $request): ?ResourceOwner
    {
        return $this->owner;
    }

    public function loginResponse(ServerRequestInterface $request, string $returnTo): ResponseInterface
    {
        $this->returnTo = $returnTo;

        return new Response(302, ['Location' => '/login?redirect=' . rawurlencode($returnTo)]);
    }
}
