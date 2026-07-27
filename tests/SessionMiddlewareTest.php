<?php

declare(strict_types=1);

namespace Safi\Extensions\Session\Tests;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\NullLogger;
use Safi\Extensions\Session\SessionMiddleware;
use Safi\Extensions\Session\SessionService;

final class SessionMiddlewareTest extends TestCase
{
    public function testAttachesSessionServiceToRequestAttributeAndCommits(): void
    {
        $session = new SessionService(new NullLogger());
        $middleware = new SessionMiddleware($session);

        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn('GET');

        $response = $this->createMock(ResponseInterface::class);
        $handler = $this->createMock(RequestHandlerInterface::class);

        $request->expects($this->once())
            ->method('withAttribute')
            ->with('session', $session)
            ->willReturn($request);

        $handler->expects($this->once())
            ->method('handle')
            ->with($request)
            ->willReturn($response);

        $result = $middleware->process($request, $handler);
        $this->assertSame($response, $result);
    }
}
