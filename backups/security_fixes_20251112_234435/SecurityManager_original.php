<?php

declare(strict_types=1);

namespace App\Security;

use App\Core\ConfigManager;
use Monolog\Logger;

/**
 * Security Manager
 * Centralized security controls and threat detection
 */
class SecurityManager
{
    private ConfigManager $config;
    private Logger $logger;
    private array $securityEvents = [];
    
    public function __construct(ConfigManager $config, Logger $logger)
    {
        $this->config = $config;
        $this->logger = $logger;
    }
    
    /**
     * Initialize secure session with hardened settings
     */
    public function initializeSecureSession(): void
    {
        // Prevent session fixation attacks
        if (session_status() === PHP_SESSION_NONE) {
            // Configure secure session settings
            ini_set('session.cookie_httponly', '1');
            ini_set('session.use_only_cookies', '1');
            ini_set('session.cookie_secure', env('APP_ENV') === 'production' ? '1' : '0');
            ini_set('session.cookie_samesite', 'Strict');
            ini_set('session.use_strict_mode', '1');
            
            // Set session lifetime
            ini_set('session.gc_maxlifetime', (string) env('SESSION_LIFETIME', 7200));
            
            // Use cryptographically secure session ID
            ini_set('session.entropy_length', '32');
            ini_set('session.hash_function', 'sha256');
            
            session_start();
            
            // Regenerate session ID on login and periodically
            if (!isset($_SESSION['initiated'])) {
                session_regenerate_id(true);
                $_SESSION['initiated'] = true;
                $_SESSION['last_regeneration'] = time();
            }
            
            // Regenerate session ID every 30 minutes
            if (time() - ($_SESSION['last_regeneration'] ?? 0) > 1800) {
                session_regenerate_id(true);
                $_SESSION['last_regeneration'] = time();
            }
            
            // Session timeout check
            if (isset($_SESSION['last_activity'])) {
                $sessionLifetime = env('SESSION_LIFETIME', 7200);
                if (time() - $_SESSION['last_activity'] > $sessionLifetime) {
                    $this->destroySession();
                    return;
                }
            }
            
            $_SESSION['last_activity'] = time();
            
            // IP address validation (prevent session hijacking)
            if (isset($_SESSION['ip_address'])) {
                if ($_SESSION['ip_address'] !== $_SERVER['REMOTE_ADDR']) {
                    $this->logSecurityEvent('session_hijacking_attempt', [
                        'original_ip' => $_SESSION['ip_address'],
                        'current_ip' => $_SERVER['REMOTE_ADDR']
                    ]);
                    $this->destroySession();
                    return;
                }
            } else {
                $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'];
            }
            
            // User agent validation
            if (isset($_SESSION['user_agent'])) {
                $currentAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
                if ($_SESSION['user_agent'] !== $currentAgent) {
                    $this->logSecurityEvent('session_user_agent_mismatch', [
                        'original_agent' => $_SESSION['user_agent'],
                        'current_agent' => $currentAgent
                    ]);
                    $this->destroySession();
                    return;
                }
            } else {
                $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
            }
        }
    }
    
    /**
     * Destroy session securely
     */
    public function destroySession(): void
    {
        $_SESSION = [];
        
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params["path"], $params["domain"],
                $params["secure"], $params["httponly"]
            );
        }
        
        session_destroy();
    }
    
    /**
     * Set security headers to prevent various attacks
     */
    public function setSecurityHeaders(): void
    {
        if (!env('SECURITY_HEADERS_ENABLED', true)) {
            return;
        }
        
        // Prevent clickjacking
        header('X-Frame-Options: DENY');
        
        // Prevent MIME type sniffing
        header('X-Content-Type-Options: nosniff');
        
        // Enable XSS protection
        header('X-XSS-Protection: 1; mode=block');
        
        // Referrer Policy
        header('Referrer-Policy: strict-origin-when-cross-origin');
        
        // Content Security Policy
        if (env('CONTENT_SECURITY_POLICY_ENABLED', true)) {
            $csp = [
                "default-src 'self'",
                "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com",
                "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com",
                "img-src 'self' data: https://www.sansouci.com.do",
                "font-src 'self' https://cdnjs.cloudflare.com",
                "connect-src 'self'",
                "frame-ancestors 'none'",
                "base-uri 'self'",
                "form-action 'self'"
            ];
            header('Content-Security-Policy: ' . implode('; ', $csp));
        }
        
        // HSTS (only in production)
        if (env('APP_ENV') === 'production') {
            $maxAge = env('HSTS_MAX_AGE', 31536000);
            header("Strict-Transport-Security: max-age={$maxAge}; includeSubDomains; preload");
        }
        
        // Feature Policy / Permissions Policy
        header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
    }
    
    /**
     * Validate and sanitize input data
     */
    public function sanitizeInput(array $data): array
    {
        $sanitized = [];
        
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $sanitized[$key] = $this->sanitizeInput($value);
            } elseif (is_string($value)) {
                // Remove potentially dangerous characters
                $value = trim($value);
                
                // Check for SQL injection patterns
                if ($this->detectSQLInjection($value)) {
                    $this->logSecurityEvent('sql_injection_attempt', [
                        'field' => $key,
                        'value' => substr($value, 0, 100) // Log first 100 chars only
                    ]);
                    throw new \Exception('Security violation detected');
                }
                
                // Check for XSS patterns
                if ($this->detectXSS($value)) {
                    $this->logSecurityEvent('xss_attempt', [
                        'field' => $key,
                        'value' => substr($value, 0, 100)
                    ]);
                }
                
                // Sanitize HTML
                $sanitized[$key] = htmlspecialchars($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            } else {
                $sanitized[$key] = $value;
            }
        }
        
        return $sanitized;
    }
    
    /**
     * Detect SQL injection patterns
     */
    private function detectSQLInjection(string $input): bool
    {
        $patterns = [
            '/(\bunion\b.*\bselect\b)/i',
            '/(\bselect\b.*\bfrom\b)/i',
            '/(\binsert\b.*\binto\b)/i',
            '/(\bupdate\b.*\bset\b)/i',
            '/(\bdelete\b.*\bfrom\b)/i',
            '/(\bdrop\b.*\btable\b)/i',
            '/(\balter\b.*\btable\b)/i',
            '/(\bcreate\b.*\btable\b)/i',
            '/(\bexec\b.*\b)/i',
            '/(\bexecute\b.*\b)/i',
            '/(;.*(\bdrop\b|\bdelete\b|\balter\b))/i',
            '/(\'\s*;\s*\w+)/i'
        ];
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $input)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Detect XSS patterns
     */
    private function detectXSS(string $input): bool
    {
        $patterns = [
            '/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/mi',
            '/javascript:/i',
            '/vbscript:/i',
            '/onload\s*=/i',
            '/onerror\s*=/i',
            '/onclick\s*=/i',
            '/onmouseover\s*=/i',
            '/<iframe\b/i',
            '/<embed\b/i',
            '/<object\b/i'
        ];
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $input)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Generate secure CSRF token
     */
    public function generateCSRFToken(): string
    {
        if (!isset($_SESSION['csrf_token']) || !isset($_SESSION['csrf_token_time'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            $_SESSION['csrf_token_time'] = time();
        }
        
        // Regenerate if expired
        $lifetime = env('CSRF_TOKEN_LIFETIME', 3600);
        if (time() - $_SESSION['csrf_token_time'] > $lifetime) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            $_SESSION['csrf_token_time'] = time();
        }
        
        return $_SESSION['csrf_token'];
    }
    
    /**
     * Verify CSRF token
     */
    public function verifyCSRFToken(string $token): bool
    {
        if (empty($token) || !isset($_SESSION['csrf_token'])) {
            return false;
        }
        
        // Check expiration
        $lifetime = env('CSRF_TOKEN_LIFETIME', 3600);
        if (time() - ($_SESSION['csrf_token_time'] ?? 0) > $lifetime) {
            return false;
        }
        
        // Timing-safe comparison
        return hash_equals($_SESSION['csrf_token'], $token);
    }
    
    /**
     * Check password strength
     */
    public function validatePasswordStrength(string $password): array
    {
        $errors = [];
        $minLength = env('PASSWORD_MIN_LENGTH', 8);
        
        if (strlen($password) < $minLength) {
            $errors[] = "Password must be at least {$minLength} characters long";
        }
        
        if (env('PASSWORD_REQUIRE_UPPERCASE', true) && !preg_match('/[A-Z]/', $password)) {
            $errors[] = 'Password must contain at least one uppercase letter';
        }
        
        if (env('PASSWORD_REQUIRE_LOWERCASE', true) && !preg_match('/[a-z]/', $password)) {
            $errors[] = 'Password must contain at least one lowercase letter';
        }
        
        if (env('PASSWORD_REQUIRE_NUMBERS', true) && !preg_match('/[0-9]/', $password)) {
            $errors[] = 'Password must contain at least one number';
        }
        
        if (env('PASSWORD_REQUIRE_SYMBOLS', true) && !preg_match('/[^A-Za-z0-9]/', $password)) {
            $errors[] = 'Password must contain at least one special character';
        }
        
        // Check against common passwords
        if ($this->isCommonPassword($password)) {
            $errors[] = 'Password is too common. Please choose a more unique password';
        }
        
        return $errors;
    }
    
    /**
     * Check if password is in common password list
     */
    private function isCommonPassword(string $password): bool
    {
        $commonPasswords = [
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey'
        ];
        
        return in_array(strtolower($password), $commonPasswords);
    }
    
    /**
     * Log security events
     */
    public function logSecurityEvent(string $event, array $context = []): void
    {
        $securityContext = [
            'event_type' => 'security_violation',
            'timestamp' => date('Y-m-d H:i:s'),
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'request_uri' => $_SERVER['REQUEST_URI'] ?? 'unknown',
            'session_id' => session_id(),
            'user_id' => $_SESSION['user']['id'] ?? null,
        ];
        
        $this->logger->warning($event, array_merge($securityContext, $context));
        
        // Store in memory for rate limiting
        $this->securityEvents[] = [
            'event' => $event,
            'timestamp' => time(),
            'context' => $context
        ];
        
        // Auto-block if too many security events
        $this->checkSecurityEventThreshold();
    }
    
    /**
     * Check if security event threshold is exceeded
     */
    private function checkSecurityEventThreshold(): void
    {
        $threshold = 5; // Max 5 security events per hour
        $timeWindow = 3600; // 1 hour
        $currentTime = time();
        
        $recentEvents = array_filter($this->securityEvents, function($event) use ($currentTime, $timeWindow) {
            return ($currentTime - $event['timestamp']) < $timeWindow;
        });
        
        if (count($recentEvents) >= $threshold) {
            // Block IP address
            $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            $this->logger->critical('IP blocked due to multiple security violations', [
                'ip_address' => $ip,
                'event_count' => count($recentEvents)
            ]);
            
            // In production, you would implement IP blocking here
            // For now, we'll just terminate the request
            http_response_code(403);
            die('Access denied due to security policy violation');
        }
    }
    
    /**
     * Generate secure random string
     */
    public function generateSecureToken(int $length = 32): string
    {
        return bin2hex(random_bytes($length / 2));
    }
}
