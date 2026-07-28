<?php

declare(strict_types=1);

namespace Safi\Extensions\Session\Tests;

use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Safi\Core\Http\Context;
use Safi\Core\Http\Request;
use Safi\Core\Http\RequestHandlerInterface;
use Safi\Core\Http\Response;
use Safi\Extensions\Session\SessionMiddleware;
use Safi\Extensions\Session\SessionService;

final class SessionMiddlewareTest extends TestCase
{
    public function testAttachesSessionServiceToRequestAttributeAndCommits(): void
    {
        $session = new SessionService(new NullLogger());
        $middleware = new SessionMiddleware($session);

        $request = new Request(server: ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/']);
        $response = new Response();
        $logger = new NullLogger();

        $context = new Context($request, $response, $logger);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())
            ->method('handle')
            ->with($context)
            ->willReturn($response);

        $result = $middleware->process($context, $handler);
        $this->assertSame($response, $result);
        $this->assertSame($session, $request->getAttribute('session'));
    }
}
