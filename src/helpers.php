<?php

declare(strict_types=1);

/**
 * Global Helper Functions
 * Security-focused utility functions for the application
 */

if (!function_exists('env')) {
    /**
     * Get environment variable with type casting and default values
     */
    function env(string $key, mixed $default = null): mixed
    {
        $value = $_ENV[$key] ?? getenv($key);
        
        if ($value === false) {
            return $default;
        }

        // Type casting for common boolean/numeric values
        switch (strtolower($value)) {
            case 'true':
            case '(true)':
                return true;
            case 'false':
            case '(false)':
                return false;
            case 'empty':
            case '(empty)':
                return '';
            case 'null':
            case '(null)':
                return null;
        }

        // Check for quoted strings
        if (strlen($value) > 1 && $value[0] === '"' && $value[-1] === '"') {
            return substr($value, 1, -1);
        }

        return $value;
    }
}

if (!function_exists('config')) {
    /**
     * Get configuration value with dot notation support
     */
    function config(string $key, mixed $default = null): mixed
    {
        static $configManager = null;
        
        if ($configManager === null) {
            $configManager = app('config');
        }
        
        return $configManager->get($key, $default);
    }
}

if (!function_exists('app')) {
    /**
     * Get instance from dependency injection container
     */
    function app(string $abstract = null): mixed
    {
        static $app = null;
        
        if ($app === null) {
            global $container;
            $app = $container;
        }
        
        if ($abstract === null) {
            return $app;
        }
        
        return $app->get($abstract);
    }
}

if (!function_exists('base_path')) {
    /**
     * Get base application path
     */
    function base_path(string $path = ''): string
    {
        return dirname(__DIR__) . ($path ? DIRECTORY_SEPARATOR . $path : $path);
    }
}

if (!function_exists('storage_path')) {
    /**
     * Get storage directory path
     */
    function storage_path(string $path = ''): string
    {
        return base_path('storage') . ($path ? DIRECTORY_SEPARATOR . $path : $path);
    }
}

if (!function_exists('public_path')) {
    /**
     * Get public directory path
     */
    function public_path(string $path = ''): string
    {
        return base_path('public') . ($path ? DIRECTORY_SEPARATOR . $path : $path);
    }
}

if (!function_exists('secure_hash')) {
    /**
     * Create secure hash using application key as salt
     */
    function secure_hash(string $value): string
    {
        return hash_hmac('sha256', $value, env('APP_KEY'));
    }
}

if (!function_exists('sanitize_input')) {
    /**
     * Sanitize user input to prevent XSS
     */
    function sanitize_input(string $input): string
    {
        return htmlspecialchars(trim($input), ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }
}

if (!function_exists('generate_csrf_token')) {
    /**
     * Generate secure CSRF token
     */
    function generate_csrf_token(): string
    {
        if (!isset($_SESSION['csrf_token']) || !isset($_SESSION['csrf_token_time'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            $_SESSION['csrf_token_time'] = time();
        }
        
        // Regenerate token if expired
        $lifetime = config('security.csrf_token_lifetime', 3600);
        if (time() - $_SESSION['csrf_token_time'] > $lifetime) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            $_SESSION['csrf_token_time'] = time();
        }
        
        return $_SESSION['csrf_token'];
    }
}

if (!function_exists('verify_csrf_token')) {
    /**
     * Verify CSRF token securely
     */
    function verify_csrf_token(string $token): bool
    {
        if (!isset($_SESSION['csrf_token']) || !isset($_SESSION['csrf_token_time'])) {
            return false;
        }
        
        // Check token expiration
        $lifetime = config('security.csrf_token_lifetime', 3600);
        if (time() - $_SESSION['csrf_token_time'] > $lifetime) {
            return false;
        }
        
        // Use timing-safe comparison
        return hash_equals($_SESSION['csrf_token'], $token);
    }
}

if (!function_exists('is_valid_email')) {
    /**
     * Validate email address securely
     */
    function is_valid_email(string $email): bool
    {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }
}

if (!function_exists('log_security_event')) {
    /**
     * Log security-related events
     */
    function log_security_event(string $event, array $context = []): void
    {
        $logger = app('logger');
        
        $securityContext = [
            'event_type' => 'security',
            'timestamp' => date('Y-m-d H:i:s'),
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'session_id' => session_id(),
        ];
        
        $logger->warning($event, array_merge($securityContext, $context));
    }
}

if (!function_exists('audit_log')) {
    /**
     * Log audit trail for compliance
     */
    function audit_log(string $action, array $data = []): void
    {
        if (!config('audit.enabled', false)) {
            return;
        }
        
        $logger = app('logger');
        
        $auditData = [
            'audit_type' => 'user_action',
            'action' => $action,
            'timestamp' => date('Y-m-d H:i:s'),
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_id' => $_SESSION['user']['id'] ?? null,
            'session_id' => session_id(),
            'data' => $data
        ];
        
        $logger->info('AUDIT: ' . $action, $auditData);
    }
}

if (!function_exists('secure_redirect')) {
    /**
     * Perform secure redirect with validation
     */
    function secure_redirect(string $url, int $code = 302): void
    {
        // Validate URL to prevent open redirect attacks
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            // If not a valid URL, check if it's a relative path
            if (!str_starts_with($url, '/')) {
                $url = '/' . $url;
            }
        }
        
        // Additional validation for external redirects
        $parsed = parse_url($url);
        if (isset($parsed['host'])) {
            $allowedHosts = config('security.allowed_redirect_hosts', []);
            if (!in_array($parsed['host'], $allowedHosts, true)) {
                log_security_event('blocked_external_redirect', ['url' => $url]);
                $url = '/'; // Fallback to home page
            }
        }
        
        header('Location: ' . $url, true, $code);
        exit;
    }
}

if (!function_exists('rate_limit_check')) {
    /**
     * Check if request exceeds rate limit
     */
    function rate_limit_check(string $key, int $maxAttempts, int $timeWindow): bool
    {
        $cacheKey = 'rate_limit:' . $key;
        $attempts = (int) ($_SESSION[$cacheKey]['count'] ?? 0);
        $firstAttempt = (int) ($_SESSION[$cacheKey]['time'] ?? time());
        
        // Reset counter if time window has passed
        if (time() - $firstAttempt > $timeWindow) {
            $_SESSION[$cacheKey] = ['count' => 1, 'time' => time()];
            return true;
        }
        
        // Check if limit exceeded
        if ($attempts >= $maxAttempts) {
            log_security_event('rate_limit_exceeded', [
                'key' => $key,
                'attempts' => $attempts,
                'max_attempts' => $maxAttempts
            ]);
            return false;
        }
        
        // Increment counter
        $_SESSION[$cacheKey]['count'] = $attempts + 1;
        return true;
    }
}
