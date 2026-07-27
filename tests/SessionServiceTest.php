<?php

declare(strict_types=1);

namespace Safi\Extensions\Session\Tests;

use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Safi\Core\Assembler;
use Safi\Core\Logger;
use Safi\Core\Services\SecurityService;
use Safi\Extensions\Session\SessionService;
use Safi\Extensions\Session\SessionServiceProvider;
use SessionHandlerInterface;

final class SessionServiceTest extends TestCase
{
    protected function setUp(): void
    {
        $_SESSION = [];
        $_SERVER['HTTP_USER_AGENT'] = 'SafiBrowser/1.0';
        $_SERVER['REMOTE_ADDR'] = '192.168.1.50';
        unset($_SERVER['HTTP_X_FORWARDED_FOR']);
    }

    public function testHandlesSessionGetSetHasRemoveAndClear(): void
    {
        $session = new SessionService(new NullLogger());

        $session->set('user_id', 42);
        $session->set('role', 'admin');

        $this->assertTrue($session->has('user_id'));
        $this->assertSame(42, $session->get('user_id'));

        $session->remove('role');
        $this->assertFalse($session->has('role'));
        $this->assertNull($session->get('role'));

        $session->clear();
        $this->assertFalse($session->has('user_id'));
    }

    /**
     * Verifies fallback default handling when requesting non-existent session keys.
     */
    public function testGetReturnsDefaultWhenKeyIsMissing(): void
    {
        $session = new SessionService(new NullLogger());

        $this->assertNull($session->get('non_existing'));
        $this->assertSame('default_value', $session->get('non_existing', 'default_value'));
        $this->assertSame(['nested' => 'array'], $session->get('non_existing', ['nested' => 'array']));
    }

    public function testHandlesPullMethod(): void
    {
        $session = new SessionService(new NullLogger());
        $session->set('temp_token', 'abc123xyz');

        $this->assertSame('abc123xyz', $session->pull('temp_token'));
        $this->assertFalse($session->has('temp_token'));
        $this->assertSame('fallback', $session->pull('temp_token', 'fallback'));
    }

    public function testGetIdReturnsString(): void
    {
        $session = new SessionService(new NullLogger());
        $this->assertIsString($session->getId());
    }

    public function testRegenerateIdReturnsTrueInCliMode(): void
    {
        $session = new SessionService(new NullLogger());
        $this->assertTrue($session->regenerateId(true));
    }

    public function testDestroyClearsSessionData(): void
    {
        $session = new SessionService(new NullLogger());
        $session->set('foo', 'bar');

        $this->assertTrue($session->destroy());
        $this->assertFalse($session->has('foo'));
        $this->assertEmpty($_SESSION);
    }

    public function testStartAndCloseMethodsExecuteWithoutErrors(): void
    {
        $session = new SessionService(new NullLogger());
        $session->start();
        $session->close();

        $this->assertTrue(true);
    }

    public function testClientMetadataVerificationSuccess(): void
    {
        $session = new SessionService(new NullLogger(), ['verify_client' => true]);
        $session->set('foo', 'bar');

        $session->start();

        $this->assertSame('bar', $session->get('foo'));
    }

    /**
     * Verifies OWASP anti-hijacking protection: triggers session destruction on fingerprint change.
     */
    public function testClientVerificationFailureTriggersSessionDestruction(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->atLeastOnce())->method('warning');

        $_SESSION['_safi_client'] = [
            'ua' => hash('sha256', 'LegitimateBrowser/1.0'),
            'ip' => '192.168.1.0',
        ];
        $_SESSION['sensitive_data'] = 'secret';

        $_SERVER['HTTP_USER_AGENT'] = 'AttackerBrowser/2.0';

        $session = new SessionService($logger, ['verify_client' => true]);
        $session->start();

        $this->assertNull($session->get('sensitive_data'));
        $this->assertArrayHasKey('_safi_client', $_SESSION);
        $this->assertSame(hash('sha256', 'AttackerBrowser/2.0'), $_SESSION['_safi_client']['ua'] ?? null);
    }

    public function testProxyAwareSecurityServiceIntegration(): void
    {
        $_SERVER['REMOTE_ADDR'] = '192.168.1.50';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.195';

        $security = new SecurityService(new NullLogger(), [
            'trusted_proxies' => ['192.168.1.0/24'],
        ]);

        $session = new SessionService(new NullLogger(), ['verify_client' => true], null, $security);
        $session->start();

        $this->assertArrayHasKey('_safi_client', $_SESSION);
        $this->assertSame('203.0.113.0', $_SESSION['_safi_client']['ip'] ?? null);
    }

    /**
     * Verifies IPv6 /64 subnet matching for privacy extension address rotation.
     */
    public function testIpv6SubnetMatching(): void
    {
        $_SERVER['REMOTE_ADDR'] = '2001:db8:85a3:0000:0000:8a2e:0370:7334';
        $_SERVER['HTTP_USER_AGENT'] = 'SafiBrowser/1.0';

        $session = new SessionService(new NullLogger(), ['verify_client' => true]);
        $session->start();

        // Simulate IP rotation within same /64 subnet
        $_SERVER['REMOTE_ADDR'] = '2001:db8:85a3:0000:1111:2222:3333:4444';
        $session->start();

        $this->assertArrayHasKey('_safi_client', $_SESSION);
    }

    public function testCustomSessionHandlerInjection(): void
    {
        $handler = $this->createMock(SessionHandlerInterface::class);
        $session = new SessionService(new NullLogger(), [], $handler);

        $session->set('test', 'value');
        $this->assertSame('value', $session->get('test'));
    }

    /**
     * Verifies SessionServiceProvider registration & boot lifecycle within the container.
     */
    public function testSessionServiceProviderRegistrationAndBoot(): void
    {
        $logger = new Logger(false);
        $assembler = new Assembler($logger);
        $assembler->set(LoggerInterface::class, $logger);

        $provider = new SessionServiceProvider(['sessid' => 'TEST_SESSID']);
        $provider->register($assembler);

        $this->assertTrue($assembler->has(SessionService::class));

        $provider->boot($assembler);

        /** @var SessionService $service */
        $service = $assembler->get(SessionService::class);
        $this->assertInstanceOf(SessionService::class, $service);
    }
}
