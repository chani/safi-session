<?php

/**
 * Safi Microframework - safi-session
 * @author Jean-Michel Brünn
 * @copyright 2026 All Rights Reserved
 * @see https://github.com/chani/safi-session
 */

declare(strict_types=1);

namespace Safi\Extensions\Session;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class SessionMiddleware implements MiddlewareInterface
{
    /**
     * @param array<string, mixed> $options Runtime start options
     * @param bool $autoInferReadOnly Automatically start GET/HEAD/OPTIONS requests in 0ms read-only mode
     */
    public function __construct(
        private SessionService $session,
        private array $options = [],
        private bool $autoInferReadOnly = true,
    ) {}

    #[\Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $options = $this->options;

        if ($this->autoInferReadOnly && !isset($options['read_only'])) {
            $method = strtoupper($request->getMethod());
            if (in_array($method, ['GET', 'HEAD', 'OPTIONS'], true)) {
                $options['read_only'] = true;
            }
        }

        $this->session->start($options);

        $request = $request->withAttribute('session', $this->session);

        try {
            return $handler->handle($request);
        } finally {
            $this->session->commit();
        }
    }
}
