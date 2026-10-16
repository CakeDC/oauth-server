<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Security;

use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use PHPUnit\Framework\TestCase;

/**
 * Secrets at rest: only hashes are stored, and client secrets are checked in constant time.
 */
class SecretsTest extends TestCase
{
    public function testTokensAndSecretsAreStoredAsHashes(): void
    {
        $harness = new ServerHarness();
        $registered = $harness->json($harness->server->registerHandler()->handle($harness->request(
            'POST',
            'https://example.com/oauth/register',
            ['Content-Type' => 'application/json'],
            '{"redirect_uris":["https://app.example.com/cb"]}',
        )));
        $client = $harness->storage->findClientByClientId($registered['client_id']);
        $this->assertNotNull($client);
        $this->assertSame(TokenGenerator::hash($registered['client_secret']), $client->secretHash);

        $code = $harness->authorizationCode($client);
        $basic = 'Basic ' . base64_encode($client->clientId . ':' . $registered['client_secret']);
        $tokens = $harness->json($harness->exchange($client, $code, [], ['Authorization' => $basic]));
        $stored = $harness->storage->findTokenByHash(TokenGenerator::hash($tokens['access_token']));
        $this->assertNotNull($stored);
        $this->assertSame(64, strlen($stored->tokenHash));

        // Nothing stored, in any form, holds a raw secret.
        $dump = serialize($harness->storage) . var_export($harness->storage, true);
        foreach ([$code, $tokens['access_token'], $registered['client_secret']] as $raw) {
            $this->assertStringNotContainsString($raw, $dump);
        }
        $this->assertNotNull($harness->storage->findCodeByHash(TokenGenerator::hash($code)));
        $this->assertNull($harness->storage->findCodeByHash($code));
    }

    public function testWrongSecretsAreRefused(): void
    {
        $harness = new ServerHarness();
        $harness->confidentialClient('right', ['clientId' => 'app']);

        $response = $harness->server->tokenHandler()->handle($harness->form(
            'https://example.com/oauth/token',
            ['grant_type' => 'client_credentials'],
            ['Authorization' => 'Basic ' . base64_encode('app:wrong')],
        ));

        $this->assertSame(401, $response->getStatusCode());
    }
}
