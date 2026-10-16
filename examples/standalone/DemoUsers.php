<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Example;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Owner\UserContextInterface;
use CakeDC\OAuth\Server\Owner\UserProviderInterface;
use CakeDC\OAuth\Server\Resource\ProtectedResource;
use Nyholm\Psr7\Response;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Two demo people and a PHP-session login. Replace both with your application's own.
 */
final class DemoUsers implements UserProviderInterface, UserContextInterface
{
    private const PEOPLE = ['alice' => 'Alice', 'bob' => 'Bob'];

    /**
     * @inheritDoc
     */
    public function findBySubject(string $subject): ?ResourceOwner
    {
        return isset(self::PEOPLE[$subject]) ? new ResourceOwner($subject, self::PEOPLE[$subject]) : null;
    }

    /**
     * @inheritDoc
     */
    public function canAuthorize(ResourceOwner $owner, Client $client, ProtectedResource $resource): bool
    {
        return true;
    }

    /**
     * @inheritDoc
     */
    public function scopesFor(ResourceOwner $owner, ProtectedResource $resource): ?array
    {
        return $owner->subject === 'bob' ? ['read'] : null;
    }

    /**
     * @inheritDoc
     */
    public function forClient(Client $client, ProtectedResource $resource): ?ResourceOwner
    {
        return null;
    }

    /**
     * @inheritDoc
     */
    public function currentOwner(ServerRequestInterface $request): ?ResourceOwner
    {
        if (getenv('OAUTH_EXAMPLE_AUTO_LOGIN') === '1') {
            return $this->findBySubject('alice');
        }
        $subject = $_SESSION['user'] ?? null;

        return is_string($subject) ? $this->findBySubject($subject) : null;
    }

    /**
     * @inheritDoc
     */
    public function loginResponse(ServerRequestInterface $request, string $returnTo): ResponseInterface
    {
        return new Response(302, ['Location' => '/login?return=' . rawurlencode($returnTo)]);
    }
}
