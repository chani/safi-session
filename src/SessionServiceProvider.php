<?php

/**
 * Safi Microframework - safi-session
 * @author Jean Bruenn
 * @copyright 2026 All Rights Reserved
 * @see https://github.com/chani/safi-session
 */

declare(strict_types=1);

namespace Safi\Extensions\Session;

use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Safi\Core\Contracts\ContainerRegistrarInterface;
use Safi\Core\Contracts\ServiceProviderInterface;
use Safi\Core\Services\SecurityService;
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

            $security = $c->has(SecurityService::class)
                ? $c->get(SecurityService::class)
                : null;

            assert($security === null || $security instanceof SecurityService);

            return new SessionService(
                $this->getLogger($c),
                $this->config,
                $handler,
                $security,
            );
        });
    }

    #[\Override]
    public function boot(ContainerInterface $container): void
    {
        /** @var SessionService $session */
        $session = $container->get(SessionService::class);
        $session->start();
    }

    private function getLogger(ContainerInterface $container): LoggerInterface
    {
        $logger = $container->get(LoggerInterface::class);
        assert($logger instanceof LoggerInterface);

        return $logger;
    }
}
