<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Storage;

/**
 * Everything the server stores.
 */
interface StorageInterface extends
    ClientRepositoryInterface,
    AuthorizationCodeRepositoryInterface,
    TokenRepositoryInterface,
    ConsentRepositoryInterface,
    MaintenanceInterface
{
}
