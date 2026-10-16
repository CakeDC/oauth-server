<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Token;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Config\Lifetimes;
use CakeDC\OAuth\Server\Event\NullEventDispatcher;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Scope\ScopeResolver;
use CakeDC\OAuth\Server\Storage\InMemory\InMemoryStorage;
use CakeDC\OAuth\Server\Support\Time;
use CakeDC\OAuth\Server\Test\Support\FakeUsers;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Testing\FrozenClock;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use CakeDC\OAuth\Server\Token\TokenIssuer;
use CakeDC\OAuth\Server\Token\TokenValidator;
use CakeDC\OAuth\Server\Token\ValidatedToken;
use CakeDC\OAuth\Server\Token\ValidationFailure;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

class TokenValidatorTest extends TestCase
{
    private InMemoryStorage $storage;

    private FrozenClock $clock;

    private FakeUsers $users;

    private TokenIssuer $issuer;

    private TokenValidator $validator;

    protected function setUp(): void
    {
        $this->storage = new InMemoryStorage();
        $this->clock = new FrozenClock();
        $this->users = new FakeUsers();
        $this->issuer = new TokenIssuer($this->storage, new TokenGenerator(), $this->clock, new NullEventDispatcher(), new Lifetimes());
        $this->validator = new TokenValidator(
            $this->storage,
            $this->storage,
            $this->users,
            Fixtures::resources(),
            new ScopeResolver(),
            $this->clock,
        );
    }

    private function token(array $scopes = ['content:publish'], ?Client $client = null): string
    {
        $client ??= Fixtures::client();
        $this->storage->saveClient($client);

        return $this->issuer->issue($client, '42', SubjectType::User, Fixtures::resources()->defaultResource(), $scopes, 'f', true)
            ->accessToken;
    }

    private function failure(string $token, string $resource = Fixtures::MCP): ValidationFailure
    {
        $result = $this->validator->validate($token, $resource);
        $this->assertInstanceOf(ValidationFailure::class, $result);

        return $result;
    }

    public function testAcceptsAValidTokenWithItsImpliedScopes(): void
    {
        $result = $this->validator->validate($this->token(), 'HTTPS://example.com/mcp/');

        $this->assertInstanceOf(ValidatedToken::class, $result);
        $this->assertSame('42', $result->owner->subject);
        $this->assertSame(['content:publish', 'content:write', 'content:read'], $result->scopes);
        $this->assertTrue($result->hasScope('content:read'));
        $this->assertSame(Fixtures::MCP, $result->resource->identifier);
    }

    public function testRejectsUnknownRefreshRevokedExpiredAndForeignTokens(): void
    {
        $this->assertSame('invalid_token', $this->failure('nope')->error);

        $client = Fixtures::client();
        $this->storage->saveClient($client);
        $issued = $this->issuer->issue($client, '42', SubjectType::User, Fixtures::resources()->defaultResource(), [], 'f', true);
        $this->failure((string)$issued->refreshToken);
        $this->assertStringContainsString('another resource', $this->failure($issued->accessToken, Fixtures::API)->description);

        $this->storage->revokeToken($issued->access->id, $this->clock->now());
        $this->assertStringContainsString('revoked', $this->failure($issued->accessToken)->description);

        $expiring = $this->token();
        $this->clock->advance(3600);
        $this->assertStringContainsString('expired', $this->failure($expiring)->description);
    }

    public function testRevokedClientsAndGoneUsersLoseAccessAtOnce(): void
    {
        $client = Fixtures::client();
        $token = $this->token([], $client);
        $this->storage->saveClient($client->withRevokedAt($this->clock->now()));
        $this->assertStringContainsString('client', $this->failure($token)->description);

        $other = $this->token();
        $this->users->remove('42');
        $this->assertStringContainsString('no longer has access', $this->failure($other)->description);
    }

    public function testScopesFollowTheOwnersCurrentScopes(): void
    {
        $token = $this->token();
        $this->users->scopes['42'] = ['content:read'];

        $result = $this->validator->validate($token, Fixtures::MCP);

        $this->assertInstanceOf(ValidatedToken::class, $result);
        $this->assertSame(['content:read'], $result->scopes);
    }

    public function testClientCredentialTokensActAsTheClientIdentity(): void
    {
        $client = Fixtures::confidentialClient();
        $this->storage->saveClient($client);
        $token = $this->issuer->issue($client, $client->clientId, SubjectType::Client, Fixtures::resources()->defaultResource(), ['content:read'], 'f', false)
            ->accessToken;

        $this->failure($token);
        $this->users->clientIdentity = new ResourceOwner($client->clientId, 'Reporting job', null, SubjectType::Client);
        $this->assertInstanceOf(ValidatedToken::class, $this->validator->validate($token, Fixtures::MCP));
    }

    public function testPersonalTokensHaveNoClient(): void
    {
        $result = $this->issuer->issuePersonal('42', Fixtures::resources()->defaultResource(), ['content:read'], 'CI', Time::plus($this->clock->now(), 86400));

        $validated = $this->validator->validate($result['value'], Fixtures::MCP);
        $this->assertInstanceOf(ValidatedToken::class, $validated);
        $this->assertNull($validated->client);
    }

    public function testPersonalTokensStopWorkingWhenTheFeatureIsOff(): void
    {
        $result = $this->issuer->issuePersonal('42', Fixtures::resources()->defaultResource(), ['content:read'], 'CI', Time::plus($this->clock->now(), 86400));
        $off = new TokenValidator(
            $this->storage,
            $this->storage,
            $this->users,
            Fixtures::resources(),
            new ScopeResolver(),
            $this->clock,
            personalTokens: false,
        );

        $failure = $off->validate($result['value'], Fixtures::MCP);

        $this->assertInstanceOf(ValidationFailure::class, $failure);
        $this->assertSame('Personal access tokens are disabled.', $failure->description);
        $this->assertInstanceOf(ValidatedToken::class, $this->validator->validate($result['value'], Fixtures::MCP));
    }

    public function testTheFlagDoesNotAffectOAuthAccessTokens(): void
    {
        $token = $this->token();
        $off = new TokenValidator(
            $this->storage,
            $this->storage,
            $this->users,
            Fixtures::resources(),
            new ScopeResolver(),
            $this->clock,
            personalTokens: false,
        );

        $this->assertInstanceOf(ValidatedToken::class, $off->validate($token, Fixtures::MCP));
    }

    public function testATokenWhoseOwnerHoldsNoScopeAnymoreIsRefused(): void
    {
        $token = $this->token(['content:write']);
        $this->users->scopes['42'] = [];

        $failure = $this->failure($token);

        $this->assertSame('The token no longer grants any scope.', $failure->description);
        $this->users->scopes['42'] = null;
        $this->assertInstanceOf(ValidatedToken::class, $this->validator->validate($token, Fixtures::MCP));
    }

    public function testRecordsUseAtMostOnceAMinute(): void
    {
        $token = $this->token();
        $hash = TokenGenerator::hash($token);

        $this->validator->validate($token, Fixtures::MCP);
        $first = $this->storage->findTokenByHash($hash)?->lastUsedAt;
        $this->clock->advance(30);
        $this->validator->validate($token, Fixtures::MCP);
        $this->assertEquals($first, $this->storage->findTokenByHash($hash)?->lastUsedAt);
        $this->clock->advance(30);
        $this->validator->validate($token, Fixtures::MCP);
        $this->assertEquals($this->clock->now(), $this->storage->findTokenByHash($hash)?->lastUsedAt);
    }

    public function testAnUndeclaredResourceIsAConfigurationError(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->validator->validate('x', 'https://other.example/mcp');
    }

    public function testTouchesTheClientWhenItTouchesTheToken(): void
    {
        $client = Fixtures::client();
        $token = $this->token(['content:read'], $client);

        $this->validator->validate($token, Fixtures::MCP);
        $first = $this->storage->findClientById($client->id)?->lastUsedAt;
        $this->assertEquals($this->clock->now(), $first);
        $this->clock->advance(30);
        $this->validator->validate($token, Fixtures::MCP);
        $this->assertEquals($first, $this->storage->findClientById($client->id)?->lastUsedAt);
        $this->clock->advance(30);
        $this->validator->validate($token, Fixtures::MCP);
        $this->assertEquals($this->clock->now(), $this->storage->findClientById($client->id)?->lastUsedAt);
    }

    public function testValidatingWithoutTouchLeavesNoTrace(): void
    {
        $client = Fixtures::client();
        $token = $this->token(['content:publish'], $client);
        $hash = TokenGenerator::hash($token);

        $result = $this->validator->validate($token, Fixtures::MCP, false);

        $this->assertInstanceOf(ValidatedToken::class, $result);
        $this->assertNull($this->storage->findTokenByHash($hash)?->lastUsedAt);
        $this->assertNull($this->storage->findClientById($client->id)?->lastUsedAt);
    }
}
