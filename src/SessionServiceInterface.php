<?php

/**
 * Safi Microframework - safi-session
 * @author Jean-Michel Brünn
 * @copyright 2026 All Rights Reserved
 * @see https://github.com/chani/safi-session
 */

declare(strict_types=1);

namespace Safi\Extensions\Session;

interface SessionServiceInterface
{
    /**
     * Starts the session with secure defaults, custom handler, and optional read-only mode.
     *
     * @param array<string, mixed> $options Runtime overrides (e.g., ['read_only' => true])
     */
    public function start(array $options = []): void;

    /**
     * Commits pending session modifications to disk/storage at request completion.
     */
    public function commit(): void;

    /**
     * Closes the session manually and releases write locks immediately.
     */
    public function close(): void;

    /**
     * Returns the active session ID.
     */
    public function getId(): string;

    /**
     * Regenerates the session ID to mitigate session fixation attacks.
     */
    public function regenerateId(bool $deleteOldSession = true): bool;

    /**
     * Destroys the session, clears session variables, and expires the session cookie.
     */
    public function destroy(): bool;

    public function clear(): void;

    public function get(string $key, mixed $default = null): mixed;

    /**
     * Retrieves an item from the session and deletes it atomically.
     */
    public function pull(string $key, mixed $default = null): mixed;

    public function set(string $key, mixed $value): void;

    public function has(string $key): bool;

    public function remove(string $key): void;

    public function isDirty(): bool;
}
