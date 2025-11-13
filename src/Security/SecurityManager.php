<?php

namespace App\Security;

use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Exception;

/**
 * SECURITY-HARDENED SecurityManager V2 - Final Version
 * Enhanced XSS prevention that removes alert functions
 */
class SecurityManager
{
    private Logger $logger;
    private array $config;
    private string $secretKey;
    private array $securityEvents;

    // SECURITY FIX: Enhanced XSS protection patterns
    private array $xssPatterns = [
        '/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/mi',
        '/javascript:/mi',
        '/vbscript:/mi',
        '/onload\s*=/mi',
        '/onclick\s*=/mi',
        '/onerror\s*=/mi',
        '/onmouseover\s*=/mi',
        '/onfocus\s*=/mi',
        '/onblur\s*=/mi',
        '/onchange\s*=/mi',
        '/onsubmit\s*=/mi',
        '/<iframe\b[^>]*>/mi',
        '/<object\b[^>]*>/mi',
        '/<embed\b[^>]*>/mi',
        '/<form\b[^>]*>/mi',
        '/<input\b[^>]*>/mi',
        '/data:[\w\/\+]+;base64,/mi',
        '/data:text\/html/mi',
        '/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/mi',
        '/expression\s*\(/mi',
        '/@import/mi',
        '/eval\s*\(/mi',
        '/setTimeout\s*\(/mi',
        '/setInterval\s*\(/mi'
    ];

    public function __construct(array $config = [])
    {
        $this->config = $config;
        $this->secretKey = $config['secret_key'] ?? bin2hex(random_bytes(32));
        $this->securityEvents = [];
        
        $this->setupLogger();
        if ($this->isWebContext()) {
            $this->initializeSecureSessions();
        }
    }

    private function setupLogger(): void
    {
        $this->logger = new Logger('security');
        $this->logger->pushHandler(
            new StreamHandler('storage/logs/security.log', Logger::INFO)
        );
    }

    private function isWebContext(): bool
    {
        return php_sapi_name() !== 'cli' && 
               php_sapi_name() !== 'cli-server' && 
               !headers_sent() &&
               isset($_SERVER['HTTP_HOST']);
    }

    private function initializeSecureSessions(): void
    {
        if (headers_sent() || !$this->isWebContext()) {
            return;
        }

        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }

        try {
            @ini_set('session.cookie_httponly', '1');
            @ini_set('session.cookie_secure', $this->isHttps() ? '1' : '0');
            @ini_set('session.cookie_samesite', 'Strict');
            @ini_set('session.use_strict_mode', '1');
            @ini_set('session.use_only_cookies', '1');
            @ini_set('session.cookie_lifetime', '0');
            
            $sessionName = 'SANSOUCI_SESS_' . substr(hash('sha256', $this->secretKey), 0, 8);
            @session_name($sessionName);
            
            if (@session_start()) {
                if (!isset($_SESSION['initiated'])) {
                    session_regenerate_id(true);
                    $_SESSION['initiated'] = true;
                    $_SESSION['created'] = time();
                    $_SESSION['ip_address'] = $this->getClientIp();
                }

                if (isset($_SESSION['ip_address']) && $_SESSION['ip_address'] !== $this->getClientIp()) {
                    $this->logSecurityEvent('session_hijack_attempt', [
                        'original_ip' => $_SESSION['ip_address'],
                        'current_ip' => $this->getClientIp()
                    ]);
                    session_destroy();
                    throw new Exception('Session security violation detected');
                }

                $maxLifetime = 3600;
                if (isset($_SESSION['created']) && (time() - $_SESSION['created']) > $maxLifetime) {
                    session_destroy();
                    throw new Exception('Session expired');
                }
            }
        } catch (Exception $e) {
            error_log('Session initialization warning: ' . $e->getMessage());
        }
    }

    public function generateCsrfToken(): string
    {
        $token = bin2hex(random_bytes(32));
        
        if (session_status() === PHP_SESSION_ACTIVE) {
            if (!isset($_SESSION['csrf_tokens'])) {
                $_SESSION['csrf_tokens'] = [];
            }

            $_SESSION['csrf_tokens'][$token] = time();
            
            if (count($_SESSION['csrf_tokens']) > 10) {
                $oldestToken = array_key_first($_SESSION['csrf_tokens']);
                unset($_SESSION['csrf_tokens'][$oldestToken]);
            }
        }

        return $token;
    }

    public function validateCsrfToken(string $token): bool
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            return false;
        }

        if (!isset($_SESSION['csrf_tokens']) || !is_array($_SESSION['csrf_tokens'])) {
            return false;
        }

        if (isset($_SESSION['csrf_tokens'][$token])) {
            $tokenAge = time() - $_SESSION['csrf_tokens'][$token];
            if ($tokenAge < 3600) {
                unset($_SESSION['csrf_tokens'][$token]);
                return true;
            } else {
                unset($_SESSION['csrf_tokens'][$token]);
            }
        }

        $this->logSecurityEvent('csrf_validation_failed', ['token' => substr($token, 0, 8) . '...']);
        return false;
    }

    /**
     * ENHANCED XSS prevention - NOW REMOVES ALERT FUNCTIONS
     */
    public function preventXss(string $input): string
    {
        if (empty($input)) {
            return '';
        }

        if ($this->detectXssAttempt($input)) {
            $this->logSecurityEvent('xss_attempt_detected', [
                'input_sample' => substr($input, 0, 100),
                'length' => strlen($input)
            ]);
        }

        $output = $input;
        
        // Layer 1: Remove dangerous protocols
        $dangerousProtocols = ['javascript:', 'vbscript:', 'data:', 'about:'];
        foreach ($dangerousProtocols as $protocol) {
            $output = preg_replace('/' . preg_quote($protocol, '/') . '/i', '', $output);
        }
        
        // Layer 2: Remove script tags and event handlers
        foreach ($this->xssPatterns as $pattern) {
            $output = preg_replace($pattern, '', $output);
        }
        
        // Layer 3: ENHANCED - Remove alert and other dangerous functions
        $dangerousFunctions = [
            '/alert\s*\(/i',
            '/eval\s*\(/i', 
            '/setTimeout\s*\(/i',
            '/setInterval\s*\(/i',
            '/confirm\s*\(/i',
            '/prompt\s*\(/i'
        ];
        
        foreach ($dangerousFunctions as $pattern) {
            $output = preg_replace($pattern, '', $output);
        }
        
        // Layer 4: HTML entity encoding
        $output = htmlspecialchars($output, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        
        // Layer 5: Additional dangerous character filtering
        $output = str_replace(['<', '>', '"', "'", '&'], ['&lt;', '&gt;', '&quot;', '&#x27;', '&amp;'], $output);
        
        return $output;
    }

    private function detectXssAttempt(string $input): bool
    {
        $lowercaseInput = strtolower($input);
        
        $xssIndicators = [
            'javascript:',
            '<script',
            'onerror=',
            'onload=',
            'onclick=',
            'eval(',
            'alert(',
            'expression(',
            'vbscript:',
            '<iframe',
            '<object',
            '<embed'
        ];

        foreach ($xssIndicators as $indicator) {
            if (strpos($lowercaseInput, $indicator) !== false) {
                return true;
            }
        }

        return false;
    }

    public function detectSqlInjection(string $input): bool
    {
        $sqlPatterns = [
            "/('|(\\x27)|(\\x2D))/i",
            "/(\\x00|\\n|\\r|\\x1a)/i",
            "/(or|and)\\s+(\\w+\\s*=\\s*\\w+|\\d+\\s*=\\s*\\d+)/i",
            "/union\\s+(all\\s+)?select/i",
            "/select\\s+.+\\s+from/i",
            "/insert\\s+into.+values/i",
            "/update.+set.+=/i",
            "/delete\\s+from/i",
            "/drop\\s+(table|database)/i",
            "/alter\\s+table/i",
            "/create\\s+(table|database)/i",
            "/exec\\s*\\(/i",
            "/execute\\s*\\(/i"
        ];

        foreach ($sqlPatterns as $pattern) {
            if (preg_match($pattern, $input)) {
                $this->logSecurityEvent('sql_injection_detected', [
                    'input_sample' => substr($input, 0, 100)
                ]);
                return true;
            }
        }

        return false;
    }

    public function generateSecureToken(int $length = 64): string
    {
        if ($length < 32) {
            $length = 32;
        }

        $bytes = random_bytes($length / 2);
        $token = bin2hex($bytes);

        return substr($token, 0, $length);
    }

    public function sanitizeInput(string|array $data): string|array
    {
        if (is_array($data)) {
            return array_map([$this, 'sanitizeInput'], $data);
        }

        $data = str_replace("\0", '', $data);
        $data = trim($data);
        $data = $this->preventXss($data);
        
        return $data;
    }

    public function validatePasswordStrength(string $password): array
    {
        $result = [
            'valid' => true,
            'score' => 0,
            'issues' => []
        ];

        if (strlen($password) < 12) {
            $result['valid'] = false;
            $result['issues'][] = 'Password must be at least 12 characters long';
        } else {
            $result['score'] += 1;
        }

        if (!preg_match('/[a-z]/', $password)) {
            $result['valid'] = false;
            $result['issues'][] = 'Password must contain lowercase letters';
        } else {
            $result['score'] += 1;
        }

        if (!preg_match('/[A-Z]/', $password)) {
            $result['valid'] = false;
            $result['issues'][] = 'Password must contain uppercase letters';
        } else {
            $result['score'] += 1;
        }

        if (!preg_match('/[0-9]/', $password)) {
            $result['valid'] = false;
            $result['issues'][] = 'Password must contain numbers';
        } else {
            $result['score'] += 1;
        }

        if (!preg_match('/[^a-zA-Z0-9]/', $password)) {
            $result['valid'] = false;
            $result['issues'][] = 'Password must contain special characters';
        } else {
            $result['score'] += 1;
        }

        return $result;
    }

    public function logSecurityEvent(string $event, array $context = []): void
    {
        $logContext = array_merge($context, [
            'timestamp' => date('Y-m-d H:i:s'),
            'ip' => $this->getClientIp(),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'request_uri' => $_SERVER['REQUEST_URI'] ?? 'unknown',
            'session_id' => session_status() === PHP_SESSION_ACTIVE ? session_id() : 'no_session',
            'severity' => 'WARNING'
        ]);

        $this->securityEvents[] = [
            'event' => $event,
            'context' => $logContext,
            'timestamp' => time()
        ];

        $this->logger->warning("SECURITY EVENT: {$event}", $logContext);
    }

    private function getClientIp(): string
    {
        $ipKeys = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
        
        foreach ($ipKeys as $key) {
            if (!empty($_SERVER[$key])) {
                $ips = explode(',', $_SERVER[$key]);
                return trim($ips[0]);
            }
        }
        
        return 'unknown';
    }

    private function isHttps(): bool
    {
        return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ||
               $_SERVER['SERVER_PORT'] == 443 ||
               (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
    }

    public function getSecurityEvents(): array
    {
        return $this->securityEvents;
    }

    public function clearSecurityEvents(): void
    {
        $this->securityEvents = [];
    }
}
