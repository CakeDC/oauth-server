<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Event;

use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Drops events, for applications that do not listen.
 */
final class NullEventDispatcher implements EventDispatcherInterface
{
    /**
     * @inheritDoc
     */
    public function dispatch(object $event): object
    {
        return $event;
    }
}
