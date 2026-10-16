<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Http\Handler;

use CakeDC\OAuth\Server\Exception\OAuthException;
use Psr\Http\Message\ResponseInterface;
use Throwable;

/**
 * Error handling of the JSON endpoints. Uses `$this->responder` and `$this->logger`.
 */
// phpcs:ignore CakePHP.NamingConventions.ValidTraitName.InvalidTraitName
trait GuardsErrors
{
    /**
     * Runs $action: OAuth errors become their JSON response, anything else a logged server_error
     * that reveals nothing. CORS headers are added either way.
     *
     * @param callable(): \Psr\Http\Message\ResponseInterface $action The endpoint logic.
     */
    private function guarded(callable $action): ResponseInterface
    {
        try {
            $response = $action();
        } catch (OAuthException $e) {
            $response = $this->responder->error($e);
        } catch (Throwable $e) {
            $this->logger->error(
                'OAuth endpoint failed: {message}',
                ['message' => $e->getMessage(), 'exception' => $e],
            );
            $response = $this->responder->error(OAuthException::serverError());
        }

        return $this->responder->withCors($response);
    }
}
