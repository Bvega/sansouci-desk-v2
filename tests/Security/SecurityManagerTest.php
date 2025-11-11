<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;
use App\Security\SecurityManager;
use App\Core\ConfigManager;
use Monolog\Logger;
use Monolog\Handler\TestHandler;

/**
 * Security Manager Test Suite
 * Tests core security functionality and threat detection
 */
class SecurityManagerTest extends TestCase
{
    private SecurityManager $security;
    private ConfigManager $config;
    private Logger $logger;
    private TestHandler $logHandler;
    
    protected function setUp(): void
    {
        // Create test logger
        $this->logHandler = new TestHandler();
        $this->logger = new Logger('test');
        $this->logger->pushHandler($this->logHandler);
        
        // Create test config
        $this->config = new ConfigManager();
        
        // Create security manager
        $this->security = new SecurityManager($this->config, $this->logger);
        
        // Clear session for each test
        if (session_status() !== PHP_SESSION_NONE) {
            session_destroy();
        }
    }
    
    /**
     * Test CSRF token generation and verification
     */
    public function testCsrfTokenGeneration(): void
    {
        session_start();
        
        $token1 = $this->security->generateCSRFToken();
        $token2 = $this->security->generateCSRFToken();
        
        // Tokens should be consistent within same session
        $this->assertEquals($token1, $token2);
        
        // Token should be valid
        $this->assertTrue($this->security->verifyCSRFToken($token1));
        
        // Invalid token should fail
        $this->assertFalse($this->security->verifyCSRFToken('invalid-token'));
        
        // Empty token should fail
        $this->assertFalse($this->security->verifyCSRFToken(''));
    }
    
    /**
     * Test SQL injection detection
     */
    public function testSQLInjectionDetection(): void
    {
        $maliciousInputs = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "UNION SELECT password FROM users",
            "admin'/*",
            "1; DELETE FROM tickets;"
        ];
        
        foreach ($maliciousInputs as $input) {
            try {
                $this->security->sanitizeInput(['test' => $input]);
                $this->fail("Expected exception for malicious input: {$input}");
            } catch (\Exception $e) {
                $this->assertStringContains('Security violation detected', $e->getMessage());
            }
        }
        
        // Verify security events were logged
        $this->assertTrue($this->logHandler->hasRecordThatContains('sql_injection_attempt'));
    }
    
    /**
     * Test XSS detection and sanitization
     */
    public function testXSSPrevention(): void
    {
        $xssInputs = [
            '<script>alert("XSS")</script>',
            'javascript:alert(1)',
            '<img src="x" onerror="alert(1)">',
            '<iframe src="javascript:alert(1)"></iframe>',
            'onmouseover="alert(1)"'
        ];
        
        foreach ($xssInputs as $input) {
            $sanitized = $this->security->sanitizeInput(['test' => $input]);
            
            // Should not contain dangerous patterns
            $this->assertStringNotContainsString('<script', $sanitized['test']);
            $this->assertStringNotContainsString('javascript:', $sanitized['test']);
            $this->assertStringNotContainsString('onerror=', $sanitized['test']);
            $this->assertStringNotContainsString('onmouseover=', $sanitized['test']);
        }
    }
    
    /**
     * Test password strength validation
     */
    public function testPasswordStrengthValidation(): void
    {
        // Weak passwords should fail
        $weakPasswords = [
            '123456',
            'password',
            'abc123',
            'qwerty',
            'admin'
        ];
        
        foreach ($weakPasswords as $password) {
            $errors = $this->security->validatePasswordStrength($password);
            $this->assertNotEmpty($errors, "Password '{$password}' should be rejected");
        }
        
        // Strong password should pass
        $strongPassword = 'SecureP@ssw0rd123!';
        $errors = $this->security->validatePasswordStrength($strongPassword);
        $this->assertEmpty($errors, "Strong password should be accepted");
    }
    
    /**
     * Test input sanitization
     */
    public function testInputSanitization(): void
    {
        $inputs = [
            'name' => '  John Doe  ',
            'email' => 'john@example.com',
            'message' => '<p>Hello <strong>world</strong></p>',
            'nested' => [
                'field1' => '  test  ',
                'field2' => '<script>alert(1)</script>'
            ]
        ];
        
        $sanitized = $this->security->sanitizeInput($inputs);
        
        // Should trim whitespace
        $this->assertEquals('John Doe', $sanitized['name']);
        
        // Email should remain unchanged
        $this->assertEquals('john@example.com', $sanitized['email']);
        
        // HTML should be escaped
        $this->assertStringContainsString('&lt;p&gt;', $sanitized['message']);
        $this->assertStringContainsString('&lt;strong&gt;', $sanitized['message']);
        
        // Nested arrays should be processed
        $this->assertEquals('test', $sanitized['nested']['field1']);
        $this->assertStringNotContainsString('<script>', $sanitized['nested']['field2']);
    }
    
    /**
     * Test security event logging
     */
    public function testSecurityEventLogging(): void
    {
        $this->security->logSecurityEvent('test_security_event', [
            'test_data' => 'test_value'
        ]);
        
        // Verify event was logged
        $this->assertTrue($this->logHandler->hasRecordThatContains('test_security_event'));
        
        // Verify context data was included
        $records = $this->logHandler->getRecords();
        $lastRecord = end($records);
        
        $this->assertArrayHasKey('test_data', $lastRecord['context']);
        $this->assertEquals('test_value', $lastRecord['context']['test_data']);
        $this->assertArrayHasKey('event_type', $lastRecord['context']);
        $this->assertEquals('security_violation', $lastRecord['context']['event_type']);
    }
    
    /**
     * Test secure token generation
     */
    public function testSecureTokenGeneration(): void
    {
        $token1 = $this->security->generateSecureToken();
        $token2 = $this->security->generateSecureToken();
        
        // Tokens should be different
        $this->assertNotEquals($token1, $token2);
        
        // Tokens should be hex strings of correct length
        $this->assertEquals(64, strlen($token1)); // 32 bytes = 64 hex chars
        $this->assertTrue(ctype_xdigit($token1));
        
        // Custom length should work
        $shortToken = $this->security->generateSecureToken(16);
        $this->assertEquals(32, strlen($shortToken)); // 16 bytes = 32 hex chars
    }
    
    /**
     * Test session security initialization
     */
    public function testSecureSessionInitialization(): void
    {
        // Mock server variables
        $_SERVER['REMOTE_ADDR'] = '192.168.1.100';
        $_SERVER['HTTP_USER_AGENT'] = 'Test Browser';
        
        $this->security->initializeSecureSession();
        
        // Session should be started
        $this->assertEquals(PHP_SESSION_ACTIVE, session_status());
        
        // Security variables should be set
        $this->assertArrayHasKey('ip_address', $_SESSION);
        $this->assertArrayHasKey('user_agent', $_SESSION);
        $this->assertArrayHasKey('last_activity', $_SESSION);
        $this->assertArrayHasKey('initiated', $_SESSION);
        
        $this->assertEquals('192.168.1.100', $_SESSION['ip_address']);
        $this->assertEquals('Test Browser', $_SESSION['user_agent']);
    }
    
    protected function tearDown(): void
    {
        if (session_status() !== PHP_SESSION_NONE) {
            session_destroy();
        }
        
        // Clean up server variables
        unset($_SERVER['REMOTE_ADDR']);
        unset($_SERVER['HTTP_USER_AGENT']);
    }
}

/**
 * Integration Test for Security Components
 */
class SecurityIntegrationTest extends TestCase
{
    /**
     * Test complete request security validation
     */
    public function testCompleteRequestSecurity(): void
    {
        // Simulate a potentially malicious request
        $_POST = [
            'username' => 'admin',
            'password' => 'password123',
            'comment' => '<script>alert("XSS")</script>',
            'sql_injection' => "'; DROP TABLE users; --"
        ];
        
        $_SERVER['REMOTE_ADDR'] = '192.168.1.100';
        $_SERVER['HTTP_USER_AGENT'] = 'Test Browser';
        
        $config = new ConfigManager();
        $logger = new Logger('test');
        $logger->pushHandler(new TestHandler());
        
        $security = new SecurityManager($config, $logger);
        
        // Start secure session
        $security->initializeSecureSession();
        
        try {
            // This should detect and block the SQL injection
            $sanitized = $security->sanitizeInput($_POST);
            $this->fail('Expected security exception for malicious input');
        } catch (\Exception $e) {
            $this->assertStringContains('Security violation detected', $e->getMessage());
        }
        
        session_destroy();
    }
    
    /**
     * Test rate limiting functionality
     */
    public function testRateLimiting(): void
    {
        $key = 'test_rate_limit';
        $maxAttempts = 3;
        $timeWindow = 60;
        
        // First 3 attempts should succeed
        for ($i = 0; $i < $maxAttempts; $i++) {
            $this->assertTrue(rate_limit_check($key, $maxAttempts, $timeWindow));
        }
        
        // 4th attempt should fail
        $this->assertFalse(rate_limit_check($key, $maxAttempts, $timeWindow));
    }
}
