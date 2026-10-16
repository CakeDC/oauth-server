<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Client;

/**
 * How a client came to exist.
 */
enum ClientType: string
{
    case Registered = 'registered';
    case Dynamic = 'dynamic';
    case MetadataDocument = 'metadata_document';
}
