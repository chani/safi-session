<?php

/**
 * Safi Microframework - safi-session
 * @author Jean-Michel Brünn
 * @copyright 2026 All Rights Reserved
 * @see https://github.com/chani/safi-session
 */

declare(strict_types=1);

namespace Safi\Extensions\Session;

use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Safi\Core\Contracts\ContainerRegistrarInterface;
use Safi\Core\Contracts\ServiceProviderInterface;
use SessionHandlerInterface;

final class SessionServiceProvider implements ServiceProviderInterface
{
    /**
     * @param array<string, mixed> $config
     */
    public function __construct(private readonly array $config = []) {}

    #[\Override]
    public function register(ContainerRegistrarInterface $registrar): void
    {
        $registrar->set(SessionService::class, function (ContainerInterface $c): SessionService {
            $handler = $c->has(SessionHandlerInterface::class)
                ? $c->get(SessionHandlerInterface::class)
                : null;

            assert($handler === null || $handler instanceof SessionHandlerInterface);

            $securityClass = 'Safi\\Core\\Services\\SecurityService';
            $security = $c->has($securityClass) ? $c->get($securityClass) : null;

            // Pure DI: Closure holds resolved instance $security without referencing container $c
            $ipResolver = static function () use ($security): string {
                if (is_object($security) && method_exists($security, 'getClientIp')) {
                    $ip = $security->getClientIp();
                    return is_string($ip) ? $ip : '';
                }
                $raw = $_SERVER['REMOTE_ADDR'] ?? null;
                return is_string($raw) ? $raw : '';
            };

            return new SessionService(
                $this->getLogger($c),
                $this->config,
                $handler,
                $ipResolver,
            );
        });

        $registrar->set(
            SessionServiceInterface::class,
            static function (ContainerInterface $c): SessionServiceInterface {
                $service = $c->get(SessionService::class);
                assert($service instanceof SessionServiceInterface);
                return $service;
            },
        );
    }

    #[\Override]
    public function boot(ContainerInterface $container): void {}

    private function getLogger(ContainerInterface $container): LoggerInterface
    {
        $logger = $container->get(LoggerInterface::class);
        assert($logger instanceof LoggerInterface);

        return $logger;
    }
}
