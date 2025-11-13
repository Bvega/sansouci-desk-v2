<?php

declare(strict_types=1);

namespace App\Core;

/**
 * HTTP Request Handler
 * Secure request handling with validation and sanitization
 */
class Request
{
    private array $get;
    private array $post;
    private array $files;
    private array $server;
    private array $headers;
    private array $routeParameters = [];
    private ?array $json = null;
    
    public function __construct(array $get = [], array $post = [], array $files = [], array $server = [], array $headers = [])
    {
        $this->get = $get;
        $this->post = $post;
        $this->files = $files;
        $this->server = $server;
        $this->headers = $headers;
    }
    
    /**
     * Get HTTP method
     */
    public function getMethod(): string
    {
        return strtoupper($this->server['REQUEST_METHOD'] ?? 'GET');
    }
    
    /**
     * Get request URI
     */
    public function getUri(): string
    {
        $uri = $this->server['REQUEST_URI'] ?? '/';
        
        // Remove query string
        if (($pos = strpos($uri, '?')) !== false) {
            $uri = substr($uri, 0, $pos);
        }
        
        return $uri;
    }
    
    /**
     * Get query string parameters
     */
    public function query(string $key = null, mixed $default = null): mixed
    {
        if ($key === null) {
            return $this->get;
        }
        
        return $this->get[$key] ?? $default;
    }
    
    /**
     * Get POST data
     */
    public function input(string $key = null, mixed $default = null): mixed
    {
        if ($key === null) {
            return array_merge($this->get, $this->post);
        }
        
        return $this->post[$key] ?? $this->get[$key] ?? $default;
    }
    
    /**
     * Get all input data
     */
    public function all(): array
    {
        return array_merge($this->get, $this->post);
    }
    
    /**
     * Get only specified keys from input
     */
    public function only(array $keys): array
    {
        $input = $this->all();
        $result = [];
        
        foreach ($keys as $key) {
            if (array_key_exists($key, $input)) {
                $result[$key] = $input[$key];
            }
        }
        
        return $result;
    }
    
    /**
     * Get all input except specified keys
     */
    public function except(array $keys): array
    {
        $input = $this->all();
        
        foreach ($keys as $key) {
            unset($input[$key]);
        }
        
        return $input;
    }
    
    /**
     * Check if input has key
     */
    public function has(string $key): bool
    {
        return array_key_exists($key, $this->all());
    }
    
    /**
     * Check if input key has value (not null/empty)
     */
    public function filled(string $key): bool
    {
        $value = $this->input($key);
        return $value !== null && $value !== '';
    }
    
    /**
     * Get JSON input data
     */
    public function json(string $key = null, mixed $default = null): mixed
    {
        if ($this->json === null) {
            $input = file_get_contents('php://input');
            $this->json = json_decode($input, true) ?? [];
        }
        
        if ($key === null) {
            return $this->json;
        }
        
        return $this->json[$key] ?? $default;
    }
    
    /**
     * Get uploaded files
     */
    public function file(string $key): ?UploadedFile
    {
        if (!isset($this->files[$key])) {
            return null;
        }
        
        $file = $this->files[$key];
        
        // Handle single file upload
        if (is_array($file) && isset($file['tmp_name'])) {
            return new UploadedFile(
                $file['tmp_name'],
                $file['name'] ?? '',
                $file['type'] ?? '',
                $file['size'] ?? 0,
                $file['error'] ?? UPLOAD_ERR_OK
            );
        }
        
        return null;
    }
    
    /**
     * Check if request has file upload
     */
    public function hasFile(string $key): bool
    {
        $file = $this->file($key);
        return $file !== null && $file->isValid();
    }
    
    /**
     * Get request header
     */
    public function header(string $key, mixed $default = null): mixed
    {
        $key = strtolower($key);
        
        // Check direct headers array first
        if (isset($this->headers[$key])) {
            return $this->headers[$key];
        }
        
        // Check $_SERVER superglobal
        $serverKey = 'HTTP_' . strtoupper(str_replace('-', '_', $key));
        if (isset($this->server[$serverKey])) {
            return $this->server[$serverKey];
        }
        
        return $default;
    }
    
    /**
     * Get client IP address
     */
    public function ip(): string
    {
        // Check for IP behind proxy
        $ipHeaders = [
            'HTTP_CF_CONNECTING_IP',     // Cloudflare
            'HTTP_X_REAL_IP',            // Nginx
            'HTTP_X_FORWARDED_FOR',      // Load balancer/proxy
            'HTTP_X_FORWARDED',          // Proxy
            'HTTP_X_CLUSTER_CLIENT_IP',  // Cluster
            'HTTP_FORWARDED_FOR',        // Proxy
            'HTTP_FORWARDED',            // Proxy
            'REMOTE_ADDR'                // Standard
        ];
        
        foreach ($ipHeaders as $header) {
            if (!empty($this->server[$header])) {
                $ip = $this->server[$header];
                
                // Handle comma-separated list (X-Forwarded-For)
                if (str_contains($ip, ',')) {
                    $ip = trim(explode(',', $ip)[0]);
                }
                
                // Validate IP address
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
                
                // Allow local IPs for development
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        
        return '127.0.0.1';
    }
    
    /**
     * Get user agent
     */
    public function userAgent(): string
    {
        return $this->server['HTTP_USER_AGENT'] ?? 'Unknown';
    }
    
    /**
     * Check if request is AJAX
     */
    public function isAjax(): bool
    {
        return $this->header('X-Requested-With') === 'XMLHttpRequest';
    }
    
    /**
     * Check if request is JSON
     */
    public function isJson(): bool
    {
        $contentType = $this->header('Content-Type', '');
        return str_contains($contentType, 'application/json');
    }
    
    /**
     * Check if request wants JSON response
     */
    public function wantsJson(): bool
    {
        $acceptable = $this->header('Accept', '');
        return str_contains($acceptable, 'application/json') || $this->isAjax();
    }
    
    /**
     * Check if request is secure (HTTPS)
     */
    public function isSecure(): bool
    {
        return $this->server['HTTPS'] ?? $this->server['HTTP_X_FORWARDED_PROTO'] ?? '' === 'https';
    }
    
    /**
     * Get route parameters
     */
    public function route(string $key = null, mixed $default = null): mixed
    {
        if ($key === null) {
            return $this->routeParameters;
        }
        
        return $this->routeParameters[$key] ?? $default;
    }
    
    /**
     * Set route parameters (called by router)
     */
    public function setRouteParameters(array $parameters): void
    {
        $this->routeParameters = $parameters;
    }
    
    /**
     * Validate and sanitize input data
     */
    public function validated(array $rules = []): array
    {
        $validator = app('validator');
        $data = $this->all();
        
        // Apply basic sanitization
        foreach ($data as $key => $value) {
            if (is_string($value)) {
                $data[$key] = trim($value);
            }
        }
        
        // Apply validation rules if provided
        if (!empty($rules)) {
            $errors = $validator->validate($data, $rules);
            
            if (!empty($errors)) {
                throw new \Exception('Validation failed: ' . implode(', ', $errors));
            }
        }
        
        // Security sanitization
        $security = app('security');
        return $security->sanitizeInput($data);
    }
    
    /**
     * Get CSRF token from request
     */
    public function csrfToken(): string
    {
        return $this->input('_token', '') 
            ?: $this->header('X-CSRF-Token', '') 
            ?: $this->header('X-XSRF-Token', '');
    }
    
    /**
     * Verify CSRF token
     */
    public function verifyCsrfToken(): bool
    {
        $token = $this->csrfToken();
        return verify_csrf_token($token);
    }
    
    /**
     * Get full URL
     */
    public function fullUrl(): string
    {
        $scheme = $this->isSecure() ? 'https' : 'http';
        $host = $this->server['HTTP_HOST'] ?? 'localhost';
        $uri = $this->server['REQUEST_URI'] ?? '/';
        
        return "{$scheme}://{$host}{$uri}";
    }
    
    /**
     * Get URL without query parameters
     */
    public function url(): string
    {
        $fullUrl = $this->fullUrl();
        
        if (($pos = strpos($fullUrl, '?')) !== false) {
            return substr($fullUrl, 0, $pos);
        }
        
        return $fullUrl;
    }
    
    /**
     * Create request from PHP globals
     */
    public static function createFromGlobals(): self
    {
        return new self(
            $_GET,
            $_POST,
            $_FILES,
            $_SERVER,
            getallheaders() ?: []
        );
    }
}

/**
 * Uploaded File Handler
 */
class UploadedFile
{
    private string $tmpName;
    private string $name;
    private string $type;
    private int $size;
    private int $error;
    
    public function __construct(string $tmpName, string $name, string $type, int $size, int $error)
    {
        $this->tmpName = $tmpName;
        $this->name = $name;
        $this->type = $type;
        $this->size = $size;
        $this->error = $error;
    }
    
    /**
     * Check if file upload was successful
     */
    public function isValid(): bool
    {
        return $this->error === UPLOAD_ERR_OK && is_uploaded_file($this->tmpName);
    }
    
    /**
     * Get original filename
     */
    public function getClientOriginalName(): string
    {
        return $this->name;
    }
    
    /**
     * Get file extension
     */
    public function getClientOriginalExtension(): string
    {
        return strtolower(pathinfo($this->name, PATHINFO_EXTENSION));
    }
    
    /**
     * Get file size in bytes
     */
    public function getSize(): int
    {
        return $this->size;
    }
    
    /**
     * Get MIME type
     */
    public function getMimeType(): string
    {
        return mime_content_type($this->tmpName) ?: $this->type;
    }
    
    /**
     * Move uploaded file to destination
     */
    public function move(string $directory, string $name = null): bool
    {
        if (!$this->isValid()) {
            return false;
        }
        
        $name = $name ?: $this->name;
        $destination = rtrim($directory, '/') . '/' . $name;
        
        // Create directory if it doesn't exist
        $dir = dirname($destination);
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }
        
        return move_uploaded_file($this->tmpName, $destination);
    }
    
    /**
     * Get upload error message
     */
    public function getErrorMessage(): string
    {
        switch ($this->error) {
            case UPLOAD_ERR_OK:
                return 'File uploaded successfully';
            case UPLOAD_ERR_INI_SIZE:
                return 'File size exceeds PHP upload_max_filesize directive';
            case UPLOAD_ERR_FORM_SIZE:
                return 'File size exceeds HTML form MAX_FILE_SIZE directive';
            case UPLOAD_ERR_PARTIAL:
                return 'File was only partially uploaded';
            case UPLOAD_ERR_NO_FILE:
                return 'No file was uploaded';
            case UPLOAD_ERR_NO_TMP_DIR:
                return 'Missing temporary folder';
            case UPLOAD_ERR_CANT_WRITE:
                return 'Failed to write file to disk';
            case UPLOAD_ERR_EXTENSION:
                return 'File upload stopped by extension';
            default:
                return 'Unknown upload error';
        }
    }
}
