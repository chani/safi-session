<?php

/**
 * Safi Microframework - safi-session
 * @author Jean Bruenn
 * @copyright 2026 All Rights Reserved
 * @see https://github.com/chani/safi-session
 */

declare(strict_types=1);

namespace Safi\Extensions\Session;

use Psr\Log\LoggerInterface;
use Safi\Core\Services\SecurityService;
use SessionHandlerInterface;

final class SessionService
{
    private bool $started = false;

    /**
     * @param array<string, mixed> $config
     */
    public function __construct(
        private readonly LoggerInterface $logger,
        private readonly array $config = [],
        private readonly ?SessionHandlerInterface $handler = null,
        private readonly ?SecurityService $security = null,
    ) {}

    /**
     * Starts the session with secure defaults, custom handler, and optional read-only mode.
     *
     * @param array<string, mixed> $options Runtime overrides (e.g., ['read_only' => true])
     */
    public function start(array $options = []): void
    {
        if ($this->started) {
            return;
        }

        if (PHP_SAPI === 'cli') {
            $sessionName = is_string($this->config['sessid'] ?? null) ? $this->config['sessid'] : 'SAFI_SESSID';
            if (($this->config['verify_client'] ?? false) && !$this->verifyClientMetadata()) {
                $this->logger->warning("Session client verification failed. Destroying session: {$sessionName}");
                $this->destroy();
                $this->initClientMetadata();
            } elseif (!isset($_SESSION['_safi_client'])) {
                $this->initClientMetadata();
            }
            $this->started = true;
            return;
        }

        if (session_status() === PHP_SESSION_ACTIVE) {
            $this->started = true;
            return;
        }

        ini_set('session.use_strict_mode', '1');

        $rawProto = $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? null;
        $proto = is_string($rawProto) ? strtolower($rawProto) : '';
        $isHttps = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || $proto === 'https';

        if ($isHttps) {
            $_SERVER['HTTPS'] = 'on';
            ini_set('session.cookie_secure', '1');
        }

        if ($this->handler instanceof \SessionHandlerInterface) {
            session_set_save_handler($this->handler, true);
        }

        $sessionName = is_string($this->config['sessid'] ?? null) ? $this->config['sessid'] : 'SAFI_SESSID';
        session_name($sessionName);

        $readOnly = (bool) ($options['read_only'] ?? $this->config['read_only'] ?? false);

        $lifetime = is_int($this->config['lifetime'] ?? null) ? $this->config['lifetime'] : 0;
        if ($lifetime > 0) {
            ini_set('session.gc_maxlifetime', (string) $lifetime);
        }

        $path = is_string($this->config['path'] ?? null) ? $this->config['path'] : '/';
        $domain = is_string($this->config['domain'] ?? null) ? $this->config['domain'] : '';
        $rawSameSite = $this->config['samesite'] ?? 'Lax';
        $sameSiteStr = is_string($rawSameSite) ? strtolower($rawSameSite) : 'lax';

        $sameSite = match ($sameSiteStr) {
            'strict' => 'Strict',
            'none' => 'None',
            default => 'Lax',
        };

        session_set_cookie_params([
            'lifetime' => $lifetime,
            'path' => $path,
            'domain' => $domain,
            'secure' => $isHttps,
            'httponly' => true,
            'samesite' => $sameSite,
        ]);

        $startOptions = $readOnly ? ['read_and_close' => true] : [];

        if (session_start($startOptions)) {
            $this->started = true;
            $this->logger->info("Session started: {$sessionName}" . ($readOnly ? ' (read-only)' : ''));

            if (($this->config['verify_client'] ?? false) && !$this->verifyClientMetadata()) {
                $this->logger->warning("Session client verification failed. Destroying session: {$sessionName}");
                $this->destroy();
                session_start($startOptions);
                $this->initClientMetadata();
            } elseif (!isset($_SESSION['_safi_client'])) {
                $this->initClientMetadata();
            }
        }
    }

    /**
     * Returns the active session ID.
     */
    public function getId(): string
    {
        $id = session_id();
        return is_string($id) ? $id : '';
    }

    /**
     * Closes the session and releases the write lock early to prevent blocking parallel requests.
     */
    public function close(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
            $this->logger->info('Session write lock released.');
        }
    }

    /**
     * Regenerates the session ID to mitigate session fixation attacks.
     */
    public function regenerateId(bool $deleteOldSession = true): bool
    {
        if (PHP_SAPI === 'cli') {
            return true;
        }

        if (session_status() !== PHP_SESSION_ACTIVE) {
            return false;
        }

        $result = session_regenerate_id($deleteOldSession);
        if ($result) {
            $this->logger->info('Session ID regenerated.');
        }

        return $result;
    }

    /**
     * Destroys the session, clears session variables, and expires the session cookie.
     */
    public function destroy(): bool
    {
        $_SESSION = [];

        if (PHP_SAPI === 'cli') {
            $this->started = false;
            return true;
        }

        if (session_status() === PHP_SESSION_NONE) {
            return true;
        }

        if (ini_get('session.use_cookies')) {
            $name = session_name();
            if (is_string($name)) {
                $params = session_get_cookie_params();
                setcookie(
                    $name,
                    '',
                    time() - 42000,
                    $params['path'],
                    $params['domain'],
                    $params['secure'],
                    $params['httponly'],
                );
            }
        }

        $destroyed = session_destroy();
        $this->started = false;

        if ($destroyed) {
            $this->logger->info('Session destroyed successfully.');
        }

        return $destroyed;
    }

    public function clear(): void
    {
        $this->assertSessionIsWritable('clear');
        $_SESSION = [];
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $_SESSION[$key] ?? $default;
    }

    /**
     * Retrieves an item from the session and deletes it atomically.
     */
    public function pull(string $key, mixed $default = null): mixed
    {
        $value = $this->get($key, $default);
        $this->remove($key);
        return $value;
    }

    public function set(string $key, mixed $value): void
    {
        $this->assertSessionIsWritable("set('{$key}')");
        $_SESSION[$key] = $value;
    }

    public function has(string $key): bool
    {
        return isset($_SESSION[$key]);
    }

    public function remove(string $key): void
    {
        $this->assertSessionIsWritable("remove('{$key}')");
        unset($_SESSION[$key]);
    }

    private function assertSessionIsWritable(string $action): void
    {
        if (PHP_SAPI !== 'cli' && session_status() !== PHP_SESSION_ACTIVE) {
            $this->logger->warning("Attempted to modify session via {$action} while write lock is closed or session is inactive.");
        }
    }

    private function initClientMetadata(): void
    {
        $rawUa = $_SERVER['HTTP_USER_AGENT'] ?? null;
        $rawIp = $this->resolveClientIp();

        $_SESSION['_safi_client'] = [
            'ua' => is_string($rawUa) ? $rawUa : 'unknown',
            'ip' => $this->getIpSubnet($rawIp),
        ];
    }

    private function verifyClientMetadata(): bool
    {
        if (!isset($_SESSION['_safi_client']) || !is_array($_SESSION['_safi_client'])) {
            return true;
        }

        $rawUa = $_SERVER['HTTP_USER_AGENT'] ?? null;
        $currentIpSubnet = $this->getIpSubnet($this->resolveClientIp());

        $currentUa = is_string($rawUa) ? $rawUa : 'unknown';

        $storedUa = is_string($_SESSION['_safi_client']['ua'] ?? null) ? $_SESSION['_safi_client']['ua'] : '';
        $storedIp = is_string($_SESSION['_safi_client']['ip'] ?? null) ? $_SESSION['_safi_client']['ip'] : '';

        return $currentUa === $storedUa && $currentIpSubnet === $storedIp;
    }

    private function resolveClientIp(): string
    {
        if ($this->security instanceof \Safi\Core\Services\SecurityService) {
            return $this->security->getClientIp();
        }

        $rawIp = $_SERVER['REMOTE_ADDR'] ?? null;
        return is_string($rawIp) ? $rawIp : '';
    }

    private function getIpSubnet(string $ip): string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $parts = explode('.', $ip);
            return $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.0';
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $packed = inet_pton($ip);
            if ($packed !== false) {
                return bin2hex(substr($packed, 0, 8));
            }
        }

        return $ip;
    }
}
