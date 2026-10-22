<?php

namespace tests;

// Keep the real probe, task runner and message formatter; replace external storage,
// DNS APIs and notification delivery so this suite cannot change live records.
class Store
{
    public array $tables = [];
    public array $dnsChanges = [];
    public array $messages = [];

    public function name($name): Query
    {
        return new Query($this, $name);
    }
}

class Query
{
    private array $conditions = [];
    private ?string $increment = null;
    private string $extra = '';

    public function __construct(private Store $store, private string $table) {}

    public function where($field, $value): self
    {
        $this->conditions[preg_replace('/^.*\./', '', $field)] = $value;
        return $this;
    }

    public function alias($alias): self { return $this; }
    public function join($table, $condition): self { return $this; }
    public function field($field): self { return $this; }
    public function extra($extra): self { $this->extra = $extra; return $this; }
    public function inc($field): self { $this->increment = $field; return $this; }

    private function matches(array $row): bool
    {
        foreach ($this->conditions as $field => $value) {
            if (($row[$field] ?? null) != $value) return false;
        }
        return true;
    }

    public function find(): ?array
    {
        foreach ($this->store->tables[$this->table] ?? [] as $row) {
            if ($this->matches($row)) return $row;
        }
        return null;
    }

    public function value($field) { return $this->find()[$field] ?? null; }

    public function insert(array $row): int
    {
        if ($this->table === 'config') {
            foreach ($this->store->tables['config'] ?? [] as $existing) {
                if ($existing['key'] === $row['key']) {
                    if ($this->extra === 'IGNORE') return 0;
                    throw new \RuntimeException('Duplicate config key');
                }
            }
        }
        $this->store->tables[$this->table][] = $row;
        return 1;
    }

    public function update(array $changes = []): int
    {
        $count = 0;
        foreach ($this->store->tables[$this->table] as &$row) {
            if (!$this->matches($row)) continue;
            $row = array_replace($row, $changes);
            if ($this->increment !== null) $row[$this->increment]++;
            $count++;
        }
        return $count;
    }

    public function delete(): int
    {
        $count = 0;
        foreach ($this->store->tables[$this->table] ?? [] as $index => $row) {
            if (!$this->matches($row)) continue;
            unset($this->store->tables[$this->table][$index]);
            $count++;
        }
        return $count;
    }
}

namespace app\lib;

class NewDb
{
    public static \tests\Store $store;
    public static function pool() { return self::$store; }
    public static function release($connection, $broken = false) {}
}

class DnsHelper
{
    public static function getModel2($domain) { return new self(); }
    public function updateDomainRecord(...$args): bool
    {
        NewDb::$store->dnsChanges[] = ['update', $args];
        return true;
    }
    public function setDomainRecordStatus(...$args): bool
    {
        NewDb::$store->dnsChanges[] = ['status', $args];
        return true;
    }
}

namespace GuzzleHttp;

class Client
{
    public function request($method, $url, $options)
    {
        \app\lib\NewDb::$store->messages[] = json_decode($options['body'], true, 512, JSON_THROW_ON_ERROR);
        return new class {
            public function getStatusCode() { return 200; }
        };
    }
}
