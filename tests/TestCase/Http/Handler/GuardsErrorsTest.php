<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\TestCase\Http\Handler;

use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Http\HttpResponder;
use CakeDC\OAuth\Server\Test\Support\GuardedHost;
use CakeDC\OAuth\Server\Test\Support\RecordingLogger;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;
use RuntimeException;

class GuardsErrorsTest extends TestCase
{
    private RecordingLogger $logger;

    private Psr17Factory $factory;

    protected function setUp(): void
    {
        $this->logger = new RecordingLogger();
        $this->factory = new Psr17Factory();
    }

    private function host(?StreamFactoryInterface $streams = null): GuardedHost
    {
        return new GuardedHost(new HttpResponder($this->factory, $streams ?? $this->factory), $this->logger);
    }

    public function testSuccessGetsCors(): void
    {
        $response = $this->host()->run(fn() => $this->factory->createResponse(200));

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('*', $response->getHeaderLine('Access-Control-Allow-Origin'));
    }

    public function testOAuthErrorsBecomeJsonWithCors(): void
    {
        $response = $this->host()->run(fn() => throw OAuthException::invalidGrant('Bad code.'));

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('*', $response->getHeaderLine('Access-Control-Allow-Origin'));
        $this->assertSame(
            '{"error":"invalid_grant","error_description":"Bad code."}',
            (string)$response->getBody(),
        );
    }

    public function testOtherFailuresAreLoggedAndRevealNothing(): void
    {
        $response = $this->host()->run(fn() => throw new RuntimeException('secret db detail'));

        $this->assertSame(500, $response->getStatusCode());
        $this->assertSame('*', $response->getHeaderLine('Access-Control-Allow-Origin'));
        $this->assertStringContainsString('server_error', (string)$response->getBody());
        $this->assertStringNotContainsString('secret db detail', (string)$response->getBody());
        $this->assertStringContainsString('secret db detail', $this->logger->text());
    }

    public function testAFailureWhileRenderingAnErrorStillGivesServerError(): void
    {
        $factory = $this->factory;
        $streams = new class ($factory) implements StreamFactoryInterface {
            private bool $failed = false;

            public function __construct(private Psr17Factory $inner)
            {
            }

            public function createStream(string $content = ''): StreamInterface
            {
                if (!$this->failed) {
                    $this->failed = true;

                    throw new RuntimeException('render failed');
                }

                return $this->inner->createStream($content);
            }

            public function createStreamFromFile(string $filename, string $mode = 'r'): StreamInterface
            {
                return $this->inner->createStreamFromFile($filename, $mode);
            }

            public function createStreamFromResource($resource): StreamInterface
            {
                return $this->inner->createStreamFromResource($resource);
            }
        };

        $response = $this->host($streams)->run(fn() => throw OAuthException::invalidGrant('x'));

        $this->assertSame(500, $response->getStatusCode());
        $this->assertSame('*', $response->getHeaderLine('Access-Control-Allow-Origin'));
        $this->assertStringContainsString('server_error', (string)$response->getBody());
        $this->assertStringContainsString('render failed', $this->logger->text());
    }
}
