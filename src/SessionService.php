<?php

declare(strict_types=1);

namespace Safi\Extensions\Session;

use Psr\Log\LoggerInterface;
use SessionHandlerInterface;

final class SessionService implements SessionServiceInterface
{
    private bool $started = false;
    private bool $dirty = false;

    /**
     * @param array<string, mixed> $config
     */
    public function __construct(
        private readonly LoggerInterface $logger,
        private readonly array $config = [],
        private readonly ?SessionHandlerInterface $handler = null,
        private readonly mixed $ipResolver = null,
    ) {
        if ($this->ipResolver !== null && !is_callable($this->ipResolver) && !is_object($this->ipResolver)) {
            throw new \InvalidArgumentException('ipResolver must be a callable, an object, or null.');
        }
    }

    #[\Override]
    public function start(array $options = []): void
    {
        if ($this->started) {
            return;
        }

        $readOnly = (bool) ($options['read_only'] ?? $this->config['read_only'] ?? false);

        if (PHP_SAPI === 'cli') {
            $this->handleCliStart();
            return;
        }

        if (session_status() === PHP_SESSION_ACTIVE) {
            $this->started = true;
            return;
        }

        $this->configureSessionSettings();

        $startOptions = $readOnly ? ['read_and_close' => true] : [];
        $sessionName = is_string($this->config['sessid'] ?? null) ? $this->config['sessid'] : 'SAFI_SESSID';

        if (!session_start($startOptions)) {
            $this->logger->error('Failed to start HTTP session', ['session_name' => $sessionName]);
            return;
        }

        $this->started = true;
        $this->logger->info('Session started', [
            'session_name' => $sessionName,
            'read_only' => $readOnly,
        ]);

        $this->validateOrInitializeClient($sessionName, $startOptions);
    }

    #[\Override]
    public function commit(): void
    {
        if (!$this->started) {
            return;
        }

        if (PHP_SAPI === 'cli') {
            $this->dirty = false;
            return;
        }

        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
            $this->logger->info('Session active write lock released on commit.');
            $this->dirty = false;
            return;
        }

        if (!$this->dirty) {
            return;
        }

        $sessionName = session_name();
        if (is_string($sessionName)) {
            $this->logger->info('Re-opening session write lock for deferred commit', ['session_name' => $sessionName]);
            $snapshot = $_SESSION;
            @session_start();
            $_SESSION = $snapshot;
            session_write_close();
            $this->logger->info('Deferred session changes committed successfully.', ['session_name' => $sessionName]);
        }

        $this->dirty = false;
    }

    #[\Override]
    public function getId(): string
    {
        $id = session_id();
        return is_string($id) ? $id : '';
    }

    #[\Override]
    public function close(): void
    {
        $this->commit();
    }

    #[\Override]
    public function regenerateId(bool $deleteOldSession = true): bool
    {
        if (PHP_SAPI === 'cli') {
            return true;
        }

        if (session_status() !== PHP_SESSION_ACTIVE) {
            $snapshot = $_SESSION;
            @session_start();
            $_SESSION = $snapshot;
        }

        $result = session_regenerate_id($deleteOldSession);
        if ($result) {
            $this->logger->info('Session ID regenerated.');
            $this->dirty = true;
        }

        return $result;
    }

    #[\Override]
    public function destroy(): bool
    {
        $_SESSION = [];
        $this->dirty = false;

        if (PHP_SAPI === 'cli') {
            $this->started = false;
            return true;
        }

        if (session_status() === PHP_SESSION_NONE) {
            @session_start();
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

    #[\Override]
    public function clear(): void
    {
        $_SESSION = [];
        $this->dirty = true;
    }

    #[\Override]
    public function get(string $key, mixed $default = null): mixed
    {
        return $_SESSION[$key] ?? $default;
    }

    #[\Override]
    public function pull(string $key, mixed $default = null): mixed
    {
        $value = $this->get($key, $default);
        $this->remove($key);
        return $value;
    }

    #[\Override]
    public function set(string $key, mixed $value): void
    {
        $_SESSION[$key] = $value;
        $this->dirty = true;
    }

    #[\Override]
    public function has(string $key): bool
    {
        return isset($_SESSION[$key]);
    }

    #[\Override]
    public function remove(string $key): void
    {
        unset($_SESSION[$key]);
        $this->dirty = true;
    }

    #[\Override]
    public function isDirty(): bool
    {
        return $this->dirty;
    }

    private function handleCliStart(): void
    {
        $sessionName = is_string($this->config['sessid'] ?? null) ? $this->config['sessid'] : 'SAFI_SESSID';
        if (($this->config['verify_client'] ?? false) && !$this->verifyClientMetadata()) {
            $this->logger->warning('Session client verification failed. Destroying session', ['session_name' => $sessionName]);
            $this->destroy();
            $this->initClientMetadata();
        } elseif (!isset($_SESSION['_safi_client'])) {
            $this->initClientMetadata();
        }
        $this->started = true;
    }

    private function configureSessionSettings(): void
    {
        ini_set('session.use_strict_mode', '1');

        $rawProto = $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? null;
        $proto = is_string($rawProto) ? strtolower($rawProto) : '';
        $isHttps = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || $proto === 'https';

        if ($isHttps) {
            $_SERVER['HTTPS'] = 'on';
            ini_set('session.cookie_secure', '1');
        }

        if ($this->handler instanceof SessionHandlerInterface) {
            session_set_save_handler($this->handler, true);
        }

        $sessionName = is_string($this->config['sessid'] ?? null) ? $this->config['sessid'] : 'SAFI_SESSID';
        session_name($sessionName);

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
    }

    /**
     * @param array<string, mixed> $startOptions
     */
    private function validateOrInitializeClient(string $sessionName, array $startOptions): void
    {
        if (($this->config['verify_client'] ?? false) && !$this->verifyClientMetadata()) {
            $this->logger->warning('Session client verification failed. Destroying session', ['session_name' => $sessionName]);
            $this->destroy();
            session_start($startOptions);
            $this->initClientMetadata();
            return;
        }

        if (!isset($_SESSION['_safi_client'])) {
            $this->initClientMetadata();
        }
    }

    private function initClientMetadata(): void
    {
        $rawUa = $_SERVER['HTTP_USER_AGENT'] ?? null;
        $uaString = is_string($rawUa) ? $rawUa : '';
        $rawIp = $this->resolveClientIp();

        $_SESSION['_safi_client'] = [
            'ua' => hash('sha256', $uaString),
            'ip' => $this->getIpSubnet($rawIp),
        ];
    }

    private function verifyClientMetadata(): bool
    {
        $client = $_SESSION['_safi_client'] ?? null;
        if (!is_array($client)) {
            return true;
        }

        $rawUa = $_SERVER['HTTP_USER_AGENT'] ?? null;
        $currentUaHash = hash('sha256', is_string($rawUa) ? $rawUa : '');
        $currentIpSubnet = $this->getIpSubnet($this->resolveClientIp());

        $storedUaHash = is_string($client['ua'] ?? null) ? $client['ua'] : '';
        $storedIpSubnet = is_string($client['ip'] ?? null) ? $client['ip'] : '';

        return hash_equals($storedUaHash, $currentUaHash) && $currentIpSubnet === $storedIpSubnet;
    }

    private function resolveClientIp(): string
    {
        if (is_callable($this->ipResolver)) {
            $resolved = ($this->ipResolver)();
            return is_string($resolved) ? $resolved : '';
        }

        if (is_object($this->ipResolver) && method_exists($this->ipResolver, 'getClientIp')) {
            $resolved = $this->ipResolver->getClientIp();
            return is_string($resolved) ? $resolved : '';
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
