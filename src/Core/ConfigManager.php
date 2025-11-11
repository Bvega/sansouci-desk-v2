<?php

declare(strict_types=1);

namespace App\Core;

/**
 * Configuration Manager
 * Centralized configuration management with validation and security
 */
class ConfigManager
{
    private array $config = [];
    private array $loaded = [];
    
    public function __construct()
    {
        $this->loadCoreConfig();
    }
    
    /**
     * Load core configuration
     */
    private function loadCoreConfig(): void
    {
        // Database configuration
        $this->config['database'] = [
            'host' => env('DB_HOST', 'localhost'),
            'port' => (int) env('DB_PORT', 3306),
            'database' => env('DB_DATABASE'),
            'username' => env('DB_USERNAME'),
            'password' => env('DB_PASSWORD'),
            'charset' => env('DB_CHARSET', 'utf8mb4'),
            'options' => [
                \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
                \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
                \PDO::ATTR_EMULATE_PREPARES => false,
                \PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci"
            ]
        ];
        
        // Security configuration
        $this->config['security'] = [
            'csrf_token_lifetime' => (int) env('CSRF_TOKEN_LIFETIME', 3600),
            'csrf_regenerate_on_login' => env('CSRF_REGENERATE_ON_LOGIN', true),
            'rate_limit_enabled' => env('RATE_LIMIT_ENABLED', true),
            'rate_limit_requests' => (int) env('RATE_LIMIT_REQUESTS', 100),
            'rate_limit_window' => (int) env('RATE_LIMIT_WINDOW', 3600),
            'rate_limit_login_attempts' => (int) env('RATE_LIMIT_LOGIN_ATTEMPTS', 5),
            'password_min_length' => (int) env('PASSWORD_MIN_LENGTH', 8),
            'password_require_uppercase' => env('PASSWORD_REQUIRE_UPPERCASE', true),
            'password_require_lowercase' => env('PASSWORD_REQUIRE_LOWERCASE', true),
            'password_require_numbers' => env('PASSWORD_REQUIRE_NUMBERS', true),
            'password_require_symbols' => env('PASSWORD_REQUIRE_SYMBOLS', true),
            'allowed_redirect_hosts' => explode(',', env('ALLOWED_REDIRECT_HOSTS', 'localhost')),
            'security_headers_enabled' => env('SECURITY_HEADERS_ENABLED', true),
            'hsts_max_age' => (int) env('HSTS_MAX_AGE', 31536000),
            'content_security_policy_enabled' => env('CONTENT_SECURITY_POLICY_ENABLED', true)
        ];
        
        // Session configuration
        $this->config['session'] = [
            'driver' => env('SESSION_DRIVER', 'file'),
            'lifetime' => (int) env('SESSION_LIFETIME', 7200),
            'encrypt' => env('SESSION_ENCRYPT', false),
            'path' => env('SESSION_PATH', '/'),
            'domain' => env('SESSION_DOMAIN'),
            'secure_cookie' => env('SESSION_SECURE_COOKIE', env('APP_ENV') === 'production'),
            'http_only' => env('SESSION_HTTP_ONLY', true),
            'same_site' => env('SESSION_SAME_SITE', 'lax')
        ];
        
        // Email configuration
        $this->config['email'] = [
            'mailer' => env('MAIL_MAILER', 'smtp'),
            'host' => env('MAIL_HOST'),
            'port' => (int) env('MAIL_PORT', 587),
            'username' => env('MAIL_USERNAME'),
            'password' => env('MAIL_PASSWORD'),
            'encryption' => env('MAIL_ENCRYPTION', 'tls'),
            'from_address' => env('MAIL_FROM_ADDRESS'),
            'from_name' => env('MAIL_FROM_NAME')
        ];
        
        // Application configuration
        $this->config['app'] = [
            'name' => env('APP_NAME', 'Sansouci Desk'),
            'env' => env('APP_ENV', 'production'),
            'debug' => env('APP_DEBUG', false),
            'url' => env('APP_URL', 'http://localhost'),
            'timezone' => env('APP_TIMEZONE', 'UTC'),
            'key' => env('APP_KEY'),
            'cipher' => 'AES-256-CBC'
        ];
        
        // Logging configuration
        $this->config['logging'] = [
            'channel' => env('LOG_CHANNEL', 'daily'),
            'level' => env('LOG_LEVEL', 'debug'),
            'days' => (int) env('LOG_DAYS', 14),
            'path' => storage_path('logs/application.log')
        ];
        
        // Cache configuration
        $this->config['cache'] = [
            'driver' => env('CACHE_DRIVER', 'file'),
            'prefix' => env('CACHE_PREFIX', 'sansouci_desk'),
            'path' => storage_path('cache')
        ];
        
        // File upload configuration
        $this->config['upload'] = [
            'max_file_size' => (int) env('MAX_FILE_SIZE', 10485760), // 10MB
            'allowed_types' => explode(',', env('ALLOWED_FILE_TYPES', 'jpg,jpeg,png,gif,pdf,txt,doc,docx')),
            'upload_path' => storage_path('uploads')
        ];
        
        // Company information
        $this->config['company'] = [
            'name' => env('COMPANY_NAME', 'Sansouci Puerto de Santo Domingo'),
            'email' => env('COMPANY_EMAIL', 'soporte@sansouci.com.do'),
            'logo' => env('COMPANY_LOGO', 'https://www.sansouci.com.do/wp-content/uploads/2020/06/logo-sansouci.png')
        ];
        
        // Audit configuration
        $this->config['audit'] = [
            'enabled' => env('AUDIT_ENABLED', true),
            'log_sensitive_data' => env('AUDIT_LOG_SENSITIVE_DATA', false),
            'retention_days' => (int) env('AUDIT_RETENTION_DAYS', 90)
        ];
    }
    
    /**
     * Get configuration value with dot notation
     */
    public function get(string $key, mixed $default = null): mixed
    {
        $keys = explode('.', $key);
        $value = $this->config;
        
        foreach ($keys as $segment) {
            if (is_array($value) && array_key_exists($segment, $value)) {
                $value = $value[$segment];
            } else {
                return $default;
            }
        }
        
        return $value;
    }
    
    /**
     * Set configuration value
     */
    public function set(string $key, mixed $value): void
    {
        $keys = explode('.', $key);
        $config = &$this->config;
        
        while (count($keys) > 1) {
            $key = array_shift($keys);
            
            if (!isset($config[$key]) || !is_array($config[$key])) {
                $config[$key] = [];
            }
            
            $config = &$config[$key];
        }
        
        $config[array_shift($keys)] = $value;
    }
    
    /**
     * Check if configuration key exists
     */
    public function has(string $key): bool
    {
        return $this->get($key) !== null;
    }
    
    /**
     * Load configuration from file
     */
    public function loadFromFile(string $path): array
    {
        if (!file_exists($path)) {
            throw new \Exception("Configuration file not found: {$path}");
        }
        
        if (in_array($path, $this->loaded)) {
            return [];
        }
        
        $config = require $path;
        
        if (!is_array($config)) {
            throw new \Exception("Configuration file must return an array: {$path}");
        }
        
        $this->loaded[] = $path;
        
        return $config;
    }
    
    /**
     * Validate required configuration
     */
    public function validateRequired(): void
    {
        $required = [
            'app.key',
            'database.host',
            'database.database',
            'database.username'
        ];
        
        $missing = [];
        
        foreach ($required as $key) {
            if (!$this->has($key) || empty($this->get($key))) {
                $missing[] = $key;
            }
        }
        
        if (!empty($missing)) {
            throw new \Exception('Missing required configuration: ' . implode(', ', $missing));
        }
        
        // Validate APP_KEY length
        $appKey = $this->get('app.key');
        if (strlen($appKey) < 32) {
            throw new \Exception('APP_KEY must be at least 32 characters long');
        }
        
        // Validate database configuration
        if ($this->get('database.port') < 1 || $this->get('database.port') > 65535) {
            throw new \Exception('Invalid database port number');
        }
    }
    
    /**
     * Get all configuration
     */
    public function all(): array
    {
        return $this->config;
    }
    
    /**
     * Get configuration for specific section
     */
    public function getSection(string $section): array
    {
        return $this->get($section, []);
    }
    
    /**
     * Merge configuration arrays
     */
    public function merge(array $config): void
    {
        $this->config = array_merge_recursive($this->config, $config);
    }
    
    /**
     * Get sensitive configuration keys (for security audit)
     */
    public function getSensitiveKeys(): array
    {
        return [
            'database.password',
            'email.password',
            'app.key'
        ];
    }
    
    /**
     * Mask sensitive values for logging
     */
    public function maskSensitive(array $data): array
    {
        $sensitiveKeys = $this->getSensitiveKeys();
        
        foreach ($sensitiveKeys as $key) {
            if ($this->has($key)) {
                $this->set($key, '***MASKED***');
            }
        }
        
        return $data;
    }
}
