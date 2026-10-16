<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Support;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Owner\UserProviderInterface;
use CakeDC\OAuth\Server\Resource\ProtectedResource;

class FakeUsers implements UserProviderInterface
{
    /**
     * @var array<string, \CakeDC\OAuth\Server\Owner\ResourceOwner>
     */
    public array $users = [];

    /**
     * @var array<string, list<string>|null>
     */
    public array $scopes = [];

    /**
     * @var list<string>
     */
    public array $blocked = [];

    public ?ResourceOwner $clientIdentity = null;

    public function __construct()
    {
        $this->add('42', 'Ada');
        $this->add('43', 'Grace');
    }

    /**
     * @param list<string>|null $scopes
     */
    public function add(string $subject, string $name, ?array $scopes = null): ResourceOwner
    {
        $owner = new ResourceOwner($subject, $name, ['id' => $subject]);
        $this->users[$subject] = $owner;
        $this->scopes[$subject] = $scopes;

        return $owner;
    }

    public function remove(string $subject): void
    {
        unset($this->users[$subject]);
    }

    public function findBySubject(string $subject): ?ResourceOwner
    {
        return $this->users[$subject] ?? null;
    }

    public function canAuthorize(ResourceOwner $owner, Client $client, ProtectedResource $resource): bool
    {
        return !in_array($owner->subject, $this->blocked, true);
    }

    public function scopesFor(ResourceOwner $owner, ProtectedResource $resource): ?array
    {
        return $this->scopes[$owner->subject] ?? null;
    }

    public function forClient(Client $client, ProtectedResource $resource): ?ResourceOwner
    {
        return $this->clientIdentity;
    }
}
