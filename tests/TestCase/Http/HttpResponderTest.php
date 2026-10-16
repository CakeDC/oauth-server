<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Http;

use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Http\HttpResponder;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\TestCase;

class HttpResponderTest extends TestCase
{
    private HttpResponder $responder;

    protected function setUp(): void
    {
        $factory = new Psr17Factory();
        $this->responder = new HttpResponder($factory, $factory);
    }

    public function testJsonIsNotCachedByDefault(): void
    {
        $response = $this->responder->json(['a' => 'b/c']);

        $this->assertSame('application/json', $response->getHeaderLine('Content-Type'));
        $this->assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        $this->assertSame('no-cache', $response->getHeaderLine('Pragma'));
        $this->assertSame('{"a":"b/c"}', (string)$response->getBody());
        $this->assertSame('{}', (string)$this->responder->json([])->getBody());
        $cached = $this->responder->json(['a' => 1], 200, [], 300);
        $this->assertSame('public, max-age=300', $cached->getHeaderLine('Cache-Control'));
    }

    public function testErrorsCarryStatusAndHeaders(): void
    {
        $response = $this->responder->error(OAuthException::invalidClient('No.', true));

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame('Basic realm="oauth"', $response->getHeaderLine('WWW-Authenticate'));
        $this->assertSame('{"error":"invalid_client","error_description":"No."}', (string)$response->getBody());
    }

    public function testErrorsNeverExposeTheTemporaryFlag(): void
    {
        $response = $this->responder->error(OAuthException::clientUnavailable('Try later.'));

        $this->assertStringNotContainsString('temporary', (string)$response->getBody());
        $this->assertStringNotContainsString('temporary', strtolower(json_encode($response->getHeaders()) ?: ''));
        $this->assertSame(['error', 'error_description'], array_keys(json_decode((string)$response->getBody(), true)));
    }

    public function testPagesCannotBeFramedCachedOrLeakTheirUrl(): void
    {
        $response = $this->responder->page('<p>Hi</p>');

        $this->assertSame('text/html; charset=utf-8', $response->getHeaderLine('Content-Type'));
        $this->assertSame('DENY', $response->getHeaderLine('X-Frame-Options'));
        $this->assertStringContainsString(
            "frame-ancestors 'none'",
            $response->getHeaderLine('Content-Security-Policy'),
        );
        $this->assertStringNotContainsString('form-action', $response->getHeaderLine('Content-Security-Policy'));
        $this->assertSame('no-referrer', $response->getHeaderLine('Referrer-Policy'));
        $this->assertSame('no-store', $response->getHeaderLine('Cache-Control'));
    }

    public function testCorsAndRedirects(): void
    {
        $preflight = $this->responder->preflight();
        $this->assertSame(204, $preflight->getStatusCode());
        $this->assertSame('*', $preflight->getHeaderLine('Access-Control-Allow-Origin'));
        $this->assertStringContainsString('Authorization', $preflight->getHeaderLine('Access-Control-Allow-Headers'));

        $redirect = $this->responder->redirect('https://app.example.com/cb?code=x', 303);
        $this->assertSame(303, $redirect->getStatusCode());
        $this->assertSame('https://app.example.com/cb?code=x', $redirect->getHeaderLine('Location'));

        $this->assertSame(
            'POST, OPTIONS',
            $this->responder->methodNotAllowed('POST, OPTIONS')->getHeaderLine('Allow'),
        );
    }
}
