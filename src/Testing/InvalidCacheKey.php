<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Testing;

use InvalidArgumentException;
use Psr\SimpleCache\InvalidArgumentException as SimpleCacheInvalidArgument;

/**
 * A cache key PSR-16 does not allow.
 */
final class InvalidCacheKey extends InvalidArgumentException implements SimpleCacheInvalidArgument
{
}
