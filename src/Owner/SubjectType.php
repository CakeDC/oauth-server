<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Owner;

/**
 * Whom a token acts for. Kept apart so a client can never pass as a user with the same identifier.
 */
enum SubjectType: string
{
    case User = 'user';
    case Client = 'client';
}
