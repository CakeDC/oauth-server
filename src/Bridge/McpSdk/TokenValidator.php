<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Bridge\McpSdk;

use CakeDC\OAuth\Server\Token\TokenValidator as CoreTokenValidator;
use CakeDC\OAuth\Server\Token\ValidationFailure;
use Mcp\Server\Authorization\AccessToken;
use Mcp\Server\Transport\Http\OAuth\AuthorizationResult;
use Mcp\Server\Transport\Http\OAuth\AuthorizationTokenValidatorInterface;

/**
 * Plugs this server into the official MCP PHP SDK: hand it to the SDK's AuthorizationMiddleware.
 * Requires mcp/sdk.
 */
final class TokenValidator implements AuthorizationTokenValidatorInterface
{
    /**
     * @param \CakeDC\OAuth\Server\Token\TokenValidator $validator The server's validator.
     * @param string $resource The MCP endpoint's resource identifier.
     */
    public function __construct(
        private readonly CoreTokenValidator $validator,
        private readonly string $resource,
    ) {
    }

    /**
     * @inheritDoc
     */
    public function validate(string $accessToken): AuthorizationResult
    {
        $result = $this->validator->validate($accessToken, $this->resource);
        if ($result instanceof ValidationFailure) {
            return AuthorizationResult::unauthorized($result->error, $result->description);
        }
        $claims = array_filter([
            'sub' => $result->owner->subject,
            'name' => $result->owner->displayName,
            'client_id' => $result->client?->clientId,
            'aud' => $result->resource->identifier,
            'exp' => $result->token->expiresAt?->getTimestamp(),
            'iat' => $result->token->createdAt->getTimestamp(),
            'subject_type' => $result->token->subjectType->value,
        ], fn(mixed $value): bool => $value !== null);

        return AuthorizationResult::allow(new AccessToken($result->scopes, $claims));
    }
}
