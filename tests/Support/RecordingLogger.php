<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Support;

use Psr\Log\AbstractLogger;
use Stringable;
use Throwable;

class RecordingLogger extends AbstractLogger
{
    /**
     * @var list<array{0: mixed, 1: string, 2: array<mixed>}>
     */
    public array $records = [];

    public function log($level, string|Stringable $message, array $context = []): void
    {
        $this->records[] = [$level, (string)$message, $context];
    }

    /**
     * Everything logged, messages and context, as one string to search.
     */
    public function text(): string
    {
        return (string)json_encode(array_map(
            fn(array $r): array => [
                $r[1],
                array_map(fn($v) => $v instanceof Throwable ? $v->getMessage() : $v, $r[2]),
            ],
            $this->records,
        ));
    }
}
