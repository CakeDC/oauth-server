<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Security;

use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9700, "Mix-Up Attacks": every authorization response names its issuer (RFC 9207).
 */
class MixUpTest extends TestCase
{
    public function testSuccessAndErrorResponsesCarryTheIssuer(): void
    {
        $harness = new ServerHarness();
        $client = $harness->publicClient();
        $harness->signIn();
        $handler = $harness->server->authorizeHandler();

        $errorUrl = $harness->authorizeUrl($client, ['response_type' => 'token']);
        $error = $handler->handle($harness->request('GET', $errorUrl));
        $this->assertSame('https://example.com', ServerHarness::redirectParams($error)['iss']);

        $harness->authorizationCode($client);
        $success = $handler->handle($harness->request('GET', $harness->authorizeUrl($client)));
        $this->assertSame('https://example.com', ServerHarness::redirectParams($success)['iss']);

        $metadata = $harness->json($harness->server->metadataHandler()->handle($harness->request('GET', '/')));
        $this->assertTrue($metadata['authorization_response_iss_parameter_supported']);
    }
}
