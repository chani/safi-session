<?php

declare(strict_types=1);

namespace Safi\Extensions\Session;

interface SessionServiceInterface
{
    public function start(array $options = []): void;
    public function commit(): void;
    public function close(): void;
    public function getId(): string;
    public function regenerateId(bool $deleteOldSession = true): bool;
    public function destroy(): bool;
    public function clear(): void;
    public function get(string $key, mixed $default = null): mixed;
    public function pull(string $key, mixed $default = null): mixed;
    public function set(string $key, mixed $value): void;
    public function has(string $key): bool;
    public function remove(string $key): void;
    public function isDirty(): bool;
}
