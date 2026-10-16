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
     * If rendering that `server_error` fails as well (a broken stream factory), the answer is a bare 500
     * without a body, built from the response factory alone. Only when the response factory itself fails
     * does the exception escape, as a last resort, to the framework's own error handling.
     *
     * @param callable(): \Psr\Http\Message\ResponseInterface $action The endpoint logic.
     */
    private function guarded(callable $action): ResponseInterface
    {
        try {
            try {
                $response = $action();
            } catch (OAuthException $e) {
                $response = $this->responder->error($e);
            }
        } catch (Throwable $e) {
            // Also reached when rendering an OAuth error fails.
            $this->logger->error(
                'OAuth endpoint failed: {message}',
                ['message' => $e->getMessage(), 'exception' => $e],
            );
            try {
                $response = $this->responder->error(OAuthException::serverError());
            } catch (Throwable $rendering) {
                $this->logger->error(
                    'Could not render the server_error response: {message}',
                    ['message' => $rendering->getMessage(), 'exception' => $rendering],
                );
                $response = $this->responder->bareServerError();
            }
        }

        return $this->responder->withCors($response);
    }
}
