<?php
declare(strict_types=1);

namespace CakeDC\OAuth\Server\Test\Support;

use Closure;
use PDO;
use PDOStatement;

/**
 * A PDO connection that runs a callback once, just before a given statement is prepared or before the
 * next transaction begins. The callback writes through the same connection (autocommit), which is what
 * a concurrent request committing in between looks like to the code under test.
 */
final class HookedPdo extends PDO
{
    /**
     * @var array<string, \Closure(\PDO): void>
     */
    private array $beforePrepare = [];

    /**
     * @var (\Closure(\PDO): void)|null
     */
    private ?Closure $beforeTransaction = null;

    /**
     * Runs $hook once, before the first statement whose SQL starts with $prefix is prepared.
     *
     * @param \Closure(\PDO): void $hook The concurrent write.
     */
    public function beforePrepare(string $prefix, Closure $hook): void
    {
        $this->beforePrepare[$prefix] = $hook;
    }

    /**
     * Runs $hook once, before the next transaction begins.
     *
     * @param \Closure(\PDO): void $hook The concurrent write.
     */
    public function beforeTransaction(Closure $hook): void
    {
        $this->beforeTransaction = $hook;
    }

    /**
     * @inheritDoc
     */
    public function prepare(string $query, array $options = []): PDOStatement|false
    {
        foreach ($this->beforePrepare as $prefix => $hook) {
            if (str_starts_with($query, $prefix)) {
                unset($this->beforePrepare[$prefix]);
                $hook($this);
            }
        }

        return parent::prepare($query, $options);
    }

    /**
     * @inheritDoc
     */
    public function beginTransaction(): bool
    {
        $hook = $this->beforeTransaction;
        $this->beforeTransaction = null;
        if ($hook !== null) {
            $hook($this);
        }

        return parent::beginTransaction();
    }
}
