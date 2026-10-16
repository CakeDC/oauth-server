<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Client;

use CakeDC\OAuth\Server\Client\ClientAuthenticator;
use CakeDC\OAuth\Server\Client\ClientAuthMethod;
use CakeDC\OAuth\Server\Client\ClientResolver;
use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Storage\InMemory\InMemoryStorage;
use CakeDC\OAuth\Server\Test\Support\Fixtures;
use CakeDC\OAuth\Server\Testing\FrozenClock;
use DateTimeImmutable;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

class ClientAuthenticatorTest extends TestCase
{
    private InMemoryStorage $storage;

    private ClientAuthenticator $authenticator;

    protected function setUp(): void
    {
        $this->storage = new InMemoryStorage();
        $this->authenticator = new ClientAuthenticator(new ClientResolver($this->storage, new FrozenClock()));
    }

    private function request(?string $basic = null): ServerRequestInterface
    {
        $request = new ServerRequest('POST', 'https://example.com/oauth/token');

        return $basic === null ? $request : $request->withHeader('Authorization', 'Basic ' . base64_encode($basic));
    }

    private function assertFails(string $error, ServerRequestInterface $request, array $body, int $status = 401): OAuthException
    {
        try {
            $this->authenticator->authenticate($request, $body);
            $this->fail('Authenticated');
        } catch (OAuthException $e) {
            $this->assertSame($error, $e->error);
            $this->assertSame($status, $e->status);

            return $e;
        }
    }

    public function testPublicClientsIdentifyWithTheirClientId(): void
    {
        $client = Fixtures::client(['clientId' => 'public-app']);
        $this->storage->saveClient($client);

        $this->assertSame($client->id, $this->authenticator->authenticate($this->request(), ['client_id' => 'public-app'])->id);
        $this->assertFails('invalid_client', $this->request(), ['client_id' => 'public-app', 'client_secret' => 'x']);
        $this->assertFails('invalid_client', $this->request(), []);
        $this->assertFails('invalid_client', $this->request(), ['client_id' => 'nobody']);
    }

    public function testConfidentialClientsUseBasicCredentials(): void
    {
        $this->storage->saveClient(Fixtures::confidentialClient('s3cret', ['clientId' => 'my app']));

        $client = $this->authenticator->authenticate($this->request('my+app:s3cret'), []);
        $this->assertSame('my app', $client->clientId);

        $e = $this->assertFails('invalid_client', $this->request('my+app:wrong'), []);
        $this->assertSame(['WWW-Authenticate' => 'Basic realm="oauth"'], $e->headers);
        $this->assertFails('invalid_client', $this->request(), ['client_id' => 'my app']);
        $this->assertFails('invalid_client', $this->request(), ['client_id' => 'my app', 'client_secret' => 's3cret']);
    }

    public function testClientSecretPost(): void
    {
        $this->storage->saveClient(Fixtures::confidentialClient('s3cret', [
            'clientId' => 'post-app',
            'authMethod' => ClientAuthMethod::SecretPost,
        ]));

        $body = ['client_id' => 'post-app', 'client_secret' => 's3cret'];
        $this->assertSame('post-app', $this->authenticator->authenticate($this->request(), $body)->clientId);
        $this->assertFails('invalid_client', $this->request(), ['client_id' => 'post-app', 'client_secret' => 'no']);
    }

    public function testRejectsTwoMethodsAndMismatches(): void
    {
        $this->storage->saveClient(Fixtures::confidentialClient('s3cret', ['clientId' => 'app']));

        $this->assertFails('invalid_request', $this->request('app:s3cret'), ['client_secret' => 's3cret'], 400);
        $this->assertFails('invalid_request', $this->request('app:s3cret'), ['client_id' => 'other'], 400);
        $this->assertFails('invalid_client', $this->request()->withHeader('Authorization', 'Basic !!!'), []);
    }

    public function testRejectsNonStringParameters(): void
    {
        $this->assertFails('invalid_request', $this->request(), ['client_id' => ['a']], 400);
        $this->assertFails('invalid_request', $this->request(), ['client_id' => 'a', 'client_secret' => ['x']], 400);
    }

    public function testRevokedClientsCannotAuthenticate(): void
    {
        $client = Fixtures::client(['clientId' => 'gone']);
        $this->storage->saveClient($client->withRevokedAt(new DateTimeImmutable()));

        $this->assertFails('invalid_client', $this->request(), ['client_id' => 'gone']);
    }
}
