<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Support;

use CakeDC\OAuth\Server\Http\Handler\GuardsErrors;
use CakeDC\OAuth\Server\Http\HttpResponder;
use Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerInterface;

/**
 * Exposes the GuardsErrors trait for tests.
 */
final class GuardedHost
{
    use GuardsErrors;

    public function __construct(private readonly HttpResponder $responder, private readonly LoggerInterface $logger)
    {
    }

    /**
     * @param callable(): \Psr\Http\Message\ResponseInterface $action
     */
    public function run(callable $action): ResponseInterface
    {
        return $this->guarded($action);
    }
}
