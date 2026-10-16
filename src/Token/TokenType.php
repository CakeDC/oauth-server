<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Token;

/**
 * Kinds of stored tokens.
 */
enum TokenType: string
{
    case Access = 'access';
    case Refresh = 'refresh';
    case Personal = 'personal';
}
