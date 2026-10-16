<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\EndToEnd;

use CakeDC\OAuth\Server\Grant\Pkce;
use CakeDC\OAuth\Server\Test\Support\ServerHarness;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Metadata document fetches are budgeted per IP at every endpoint that resolves a client_id.
 */
class CimdFetchBudgetTest extends TestCase
{
    private ServerHarness $harness;

    protected function setUp(): void
    {
        $this->harness = new ServerHarness(['rateLimit' => ['cimd' => [2, 60]]]);
    }

    private function document(int $i): string
    {
        $id = 'https://client.example/c/' . $i;
        $this->harness->transport->serve($id, [
            'client_id' => $id,
            'client_name' => 'C' . $i,
            'redirect_uris' => ['https://client.example/cb'],
        ]);

        return $id;
    }

    private function from(string $ip, ServerRequestInterface $request): ServerRequestInterface
    {
        return new ServerRequest(
            $request->getMethod(),
            $request->getUri(),
            $request->getHeaders(),
            (string)$request->getBody(),
            '1.1',
            ['REMOTE_ADDR' => $ip],
        );
    }

    private function token(string $clientId, string $ip = ServerHarness::IP): ResponseInterface
    {
        return $this->harness->server->tokenHandler()->handle($this->from($ip, $this->harness->form(
            'https://example.com/oauth/token',
            [
                'grant_type' => 'authorization_code',
                'code' => 'x',
                'code_verifier' => ServerHarness::VERIFIER,
                'client_id' => $clientId,
            ],
        )));
    }

    private function authorize(string $clientId, string $ip = ServerHarness::IP): ResponseInterface
    {
        $url = 'https://example.com/oauth/authorize?' . http_build_query([
            'response_type' => 'code',
            'client_id' => $clientId,
            'redirect_uri' => 'https://client.example/cb',
            'state' => 's',
            'code_challenge' => Pkce::challengeFor(ServerHarness::VERIFIER),
            'code_challenge_method' => 'S256',
        ]);

        return $this->harness->server->authorizeHandler()->handle($this->from($ip, $this->harness->request('GET', $url)));
    }

    public function testTokenEndpointCutsOneIpOffAndLeavesAnotherAlone(): void
    {
        $this->assertNotSame(429, $this->token($this->document(1))->getStatusCode());
        $this->assertNotSame(429, $this->token($this->document(2))->getStatusCode());

        $response = $this->token($this->document(3));

        $this->assertSame(429, $response->getStatusCode());
        $this->assertNotSame('', $response->getHeaderLine('Retry-After'));
        $this->assertCount(2, $this->harness->transport->requests);
        $this->assertNotSame(429, $this->token($this->document(3), '198.51.100.9')->getStatusCode());
        $this->assertCount(3, $this->harness->transport->requests);
    }

    public function testAuthorizeAnswersAnErrorPageNeverARedirect(): void
    {
        $this->authorize($this->document(1));
        $this->authorize($this->document(2));

        $response = $this->authorize($this->document(3));

        $this->assertSame(429, $response->getStatusCode());
        $this->assertSame('', $response->getHeaderLine('Location'));
        $this->assertStringContainsString('text/html', $response->getHeaderLine('Content-Type'));
        $this->assertCount(2, $this->harness->transport->requests);
    }

    public function testKnownClientsCostNothing(): void
    {
        $id = $this->document(1);
        for ($i = 0; $i < 6; $i++) {
            $this->assertNotSame(429, $this->authorize($id)->getStatusCode());
        }

        $this->assertCount(1, $this->harness->transport->requests);
    }

    public function testRevokeAndIntrospectAreBudgetedToo(): void
    {
        $revoke = fn(string $id): ResponseInterface => $this->harness->server->revokeHandler()->handle(
            $this->harness->form('https://example.com/oauth/revoke', ['token' => 'x', 'client_id' => $id]),
        );
        $revoke($this->document(1));
        $revoke($this->document(2));

        $this->assertSame(429, $revoke($this->document(3))->getStatusCode());
    }
}
