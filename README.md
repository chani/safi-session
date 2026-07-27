# Safi Microframework – Session Extension (`safi-session`)

A lightweight, secure, and pluggable session management extension for the Safi Microframework.

---

## Architecture & Core Concepts

### 1. Mitigating Session Blocking (Concurrency & Performance)

#### The Problem in PHP
By default, PHP locks the session file (or Redis key) when `session_start()` is called using an exclusive lock (`LOCK_EX`). This lock is scoped **per session ID** (per individual user) and persists for the entire duration of the HTTP request.

While different visitors never block each other, concurrent requests from the **same user** (e.g., opening multiple tabs or sending simultaneous AJAX/Fetch calls in SPAs) will be queued and processed serially.

#### Solutions in `safi-session`

1. **Early Lock Release via `close()`**
   Read or update session data early in your controller lifecycle, then immediately call `$session->close()`. This releases the session lock so long-running operations (such as database queries or external API calls) can execute without blocking concurrent requests from the same client.

2. **Read-Only Sessions (`read_and_close`)**
   For requests that only require reading session data (e.g., verifying if a user is authenticated), the session can be started in read-only mode. PHP reads the data into memory and immediately closes the write lock:
   ```php
   $session->start(['read_only' => true]);
   ```

---

### 2. Authentication, Security & Utility Features

* **Session Fixation Protection (`regenerateId`)**: Call `$session->regenerateId(true)` upon login or privilege escalation to issue a fresh session identifier, preventing session fixation exploits.
* **Clean Logout (`destroy`)**: Empties `$_SESSION`, clears the session cookie in the client browser with an expired timestamp, and invokes `session_destroy()`.
* **Proxy-Aware Device Tracking (`verify_client`)**:
  When `verify_client` is enabled, `safi-session` stores the client's `User-Agent` and IP subnet (`/24` for IPv4, `/64` for IPv6). If integrated with `safi-core`'s `SecurityService`, it respects trusted proxies (`X-Forwarded-For`, `CF-Connecting-IP`).
* **Atomic Operations (`pull`)**: Atomically fetches and removes a key in a single step via `$session->pull('key')`.

---

### 3. Pluggable Storage Handlers (`SessionHandlerInterface`)

`safi-session` natively leverages PHP's built-in `SessionHandlerInterface`. When a service implementing this interface (such as a Redis or PDO handler) is registered in the DI container, it is automatically bound via `session_set_save_handler()` prior to starting the session.

---

## Configuration Example

```php
$config = [
    'sessid'        => 'SAFI_SESSID',
    'lifetime'      => 0,
    'path'          => '/',
    'domain'        => '',
    'samesite'      => 'Lax',
    'read_only'     => false,
    'verify_client' => true, // Enables device tracking against hijacking
];
```
