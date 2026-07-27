# Safi Session Extension (`safi-session`)

`safi-session` is an isolated PHP 8.5+ session management library engineered to prevent request blocking during concurrent HTTP requests while enforcing client fingerprinting controls.

It operates without required framework dependencies and can be integrated standalone, into any PSR-15 compliant HTTP pipeline, or as a component within the Safi Microframework.

---

## Technical Overview

### 1. Concurrency Control & Read-Only Inference
Standard PHP session management (`session_start()`) acquires an exclusive lock (`LOCK_EX`) on the session storage resource. Simultaneous HTTP requests sharing the same session identifier (such as multiple browser tabs or concurrent SPA fetch operations) are queued and executed serially until the lock is released.

`safi-session` mitigates request blocking via two mechanisms:
* **HTTP Method Inference:** `GET`, `HEAD`, and `OPTIONS` requests trigger `session_start(['read_and_close' => true])`. Session state is loaded into `$_SESSION` and the storage lock is released immediately at request start (0ms lock duration).
* **Deferred Locking (Dirty State Tracking):** If session state is modified (`set()`, `remove()`, `clear()`) during a read-only request, modifications are buffered in memory. The storage lock is acquired briefly at request completion via `commit()` to persist changes.

### 2. Client Hijacking & Subnet Protection (µADR-021 / µADR-035)
When `verify_client` is enabled, session initialization records and validates client metadata:
* **User-Agent SHA-256 Fingerprint:** User-Agent headers are hashed using SHA-256 and verified using constant-time comparison (`hash_equals`).
* **IP Subnet Masking:** Network matching applies CIDR masking (`/24` for IPv4, `/64` for IPv6). This prevents session invalidation caused by standard mobile network handoffs or client-side IPv6 privacy extension address rotations.

---

## Installation

```bash
composer require chani/safi-session
```

---

## How-To Guides

### How to Use Standalone in Native PHP

```php
use Safi\Extensions\Session\SessionService;
use Safi\Extensions\Session\SessionServiceInterface;
use Psr\Log\NullLogger;

/** @var SessionServiceInterface $session */
$session = new SessionService(
    logger: new NullLogger(),
    config: [
        'sessid'        => 'APP_SESSID',
        'lifetime'      => 86400,
        'samesite'      => 'Lax',
        'verify_client' => true,
    ],
    // Optional IP resolution callback or service object with getClientIp(): string
    ipResolver: fn(): string => $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? ''
);

// Start session
$session->start();

// Mutate state
$session->set('user_id', 101);

// Read state
$userId = $session->get('user_id');

// Atomic fetch-and-delete
$flash = $session->pull('flash_message');

// Commit state modifications and release locks
$session->commit();
```

---

### How to Integrate with PSR-15 Pipelines

`SessionMiddleware` implements `Psr\Http\Server\MiddlewareInterface`. It can be attached to any PSR-15 compliant request handler or middleware stack:

```php
use Safi\Extensions\Session\SessionService;
use Safi\Extensions\Session\SessionMiddleware;
use Psr\Log\NullLogger;

$sessionService = new SessionService(
    logger: new NullLogger(),
    config: ['verify_client' => true]
);

// Instantiate PSR-15 middleware with automatic read-only inference for GET requests
$middleware = new SessionMiddleware($sessionService, autoInferReadOnly: true);

// Add $middleware to your application pipeline.
// The active SessionServiceInterface instance is injected into request attributes as 'session'.
```

Inside a downstream request handler or controller:

```php
use Safi\Extensions\Session\SessionServiceInterface;
use Psr\Http\Message\ServerRequestInterface;

public function handle(ServerRequestInterface $request)
{
    /** @var SessionServiceInterface $session */
    $session = $request->getAttribute('session');
    $userId = $session->get('user_id');
}
```

---

### How to Integrate with Safi Microframework

Register `SessionServiceProvider` in your composition root (`init.inc.php`):

```php
use Safi\Extensions\Session\SessionServiceProvider;

$componentManager->bootProviders([
    new SessionServiceProvider([
        'sessid' => 'SAFI_SESSID',
        'verify_client' => true,
    ]),
]);
```

---

## Reference

### `SessionServiceInterface` API

All session operations comply with `Safi\Extensions\Session\SessionServiceInterface`.

| Method | Signature | Description |
| :--- | :--- | :--- |
| `start()` | `start(array $options = []): void` | Initializes the session using configured parameters or runtime overrides. |
| `get()` | `get(string $key, mixed$default = null): mixed` | Returns the stored value or fallback default. |
| `set()` | `set(string $key, mixed$value): void` | Assigns a session value and marks state as dirty. |
| `has()` | `has(string $key): bool` | Determines whether a key exists in session memory. |
| `remove()` | `remove(string $key): void` | Unsets a key and marks state as dirty. |
| `pull()` | `pull(string $key, mixed$default = null): mixed` | Fetches and unsets a key in a single step. |
| `clear()` | `clear(): void` | Clears all session keys and marks state as dirty. |
| `commit()` | `commit(): void` | Flushes dirty state changes to persistent storage and releases locks. |
| `close()` | `close(): void` | Manually commits and closes the active write lock. |
| `regenerateId()` | `regenerateId(bool $deleteOld = true): bool` | Issues a new session identifier to prevent session fixation. |
| `destroy()` | `destroy(): bool` | Clears variables, expires client cookies, and destroys active storage. |
| `isDirty()` | `isDirty(): bool` | Returns true if session state has uncommitted changes. |

### Configuration Parameters

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `sessid` | `string` | `'SAFI_SESSID'` | Session cookie identifier name. |
| `lifetime` | `int` | `0` | Cookie max lifetime in seconds (`0` = session duration). |
| `path` | `string` | `'/'` | Path scoping for session cookie. |
| `domain` | `string` | `''` | Domain scoping for session cookie. |
| `samesite` | `string` | `'Lax'` | SameSite cookie attribute (`'Lax'`, `'Strict'`, `'None'`). |
| `read_only` | `bool` | `false` | Global default read-only flag. |
| `verify_client` | `bool` | `false` | Enables SHA-256 User-Agent fingerprinting and subnet validation. |

---

## License

Distributed under the **MIT License**. Author: **Jean-Michel Brünn**
