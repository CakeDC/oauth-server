<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Security;

use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use CakeDC\OAuth\Server\Token\ValidatedToken;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9700, "Client Impersonating Resource Owner": a client acting for itself can never pass as a
 * person whose identifier equals its client_id.
 */
class ClientImpersonationTest extends TestCase
{
    public function testClientTokensActAsTheClientIdentityOnly(): void
    {
        $harness = new ServerHarness();
        $harness->confidentialClient('s', ['clientId' => '42']);
        $harness->users->clientIdentity = new ResourceOwner('42', 'Robot', null, SubjectType::Client);

        $token = $harness->json($harness->server->tokenHandler()->handle($harness->form(
            'https://example.com/oauth/token',
            ['grant_type' => 'client_credentials'],
            ['Authorization' => 'Basic ' . base64_encode('42:s')],
        )))['access_token'];
        $validated = $harness->server->tokenValidator()->validate($token, Fixtures::MCP);

        $this->assertInstanceOf(ValidatedToken::class, $validated);
        $this->assertSame('Robot', $validated->owner->displayName);
        $this->assertSame(SubjectType::Client, $validated->owner->type);
        $this->assertSame([], $harness->server->connectionService()->connections($harness->users->users['42']));
    }
}
