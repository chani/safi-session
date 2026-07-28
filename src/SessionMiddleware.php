<?php

/**
 * Safi Microframework - safi-session
 * @author Jean-Michel Brünn
 * @copyright 2026 All Rights Reserved
 * @see https://github.com/chani/safi-session
 */

declare(strict_types=1);

namespace Safi\Extensions\Session;

use Safi\Core\Http\Context;
use Safi\Core\Http\MiddlewareInterface;
use Safi\Core\Http\RequestHandlerInterface;
use Safi\Core\Http\Response;

final readonly class SessionMiddleware implements MiddlewareInterface
{
    /**
     * @param array<string, mixed> $options Runtime start options
     * @param bool $autoInferReadOnly Automatically start GET/HEAD/OPTIONS requests in 0ms read-only mode
     */
    public function __construct(
        private SessionServiceInterface $session,
        private array $options = [],
        private bool $autoInferReadOnly = true,
    ) {}

    #[\Override]
    public function process(Context $context, RequestHandlerInterface $handler): Response
    {
        $options = $this->options;

        if ($this->autoInferReadOnly && !isset($options['read_only'])) {
            $method = strtoupper($context->request->getMethod());
            if (in_array($method, ['GET', 'HEAD', 'OPTIONS'], true)) {
                $options['read_only'] = true;
            }
        }

        $this->session->start($options);

        $context->request->setAttribute('session', $this->session);

        try {
            return $handler->handle($context);
        } finally {
            $this->session->commit();
        }
    }
}
