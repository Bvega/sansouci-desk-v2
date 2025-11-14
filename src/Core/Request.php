<?php

namespace App\Core;

use InvalidArgumentException;

/**
 * ROBUST TYPE-IMPROVED Request (HTTP Request Handling)
 * Fixes PHPStan Level 8 array type issues with HTTP-specific types
 */
class Request
{
    /**
     * @var array<string, string> HTTP GET parameters
     */
    private array $get = [];
    
    /**
     * @var array<string, mixed> HTTP POST data (strings, arrays, files)
     */
    private array $post = [];
    
    /**
     * @var array<string, array<string, mixed>> Uploaded files ($_FILES structure)
     */
    private array $files = [];
    
    /**
     * @var array<string, string> Server environment variables
     */
    private array $server = [];
    
    /**
     * @var array<string, string> Route parameters from URL routing
     */
    private array $routeParameters = [];

    /**
     * Request constructor
     * 
     * @param array<string, string> $get GET parameters
     * @param array<string, mixed> $post POST data  
     * @param array<string, array<string, mixed>> $files Uploaded files
     * @param array<string, string> $server Server variables
     */
    public function __construct(
        array $get = [],
        array $post = [],
        array $files = [],
        array $server = []
    ) {
        $this->get = $get;
        $this->post = $post;
        $this->files = $files;
        $this->server = $server;
        $this->routeParameters = [];
    }

    /**
     * Create Request from PHP globals
     * 
     * @return self Request instance from globals
     */
    public static function createFromGlobals(): self
    {
        return new self($_GET, $_POST, $_FILES, $_SERVER);
    }

    /**
     * Get input value with fallback priority: POST -> GET -> route parameters
     * 
     * @param string $key Parameter key
     * @param mixed $default Default value
     * @return mixed Parameter value or default
     */
    public function input(string $key, mixed $default = null): mixed
    {
        return $this->post[$key] 
            ?? $this->get[$key] 
            ?? $this->routeParameters[$key] 
            ?? $default;
    }

    /**
     * Get query string (GET) parameter
     * 
     * @param string $key Parameter key
     * @param string|null $default Default value
     * @return string|null Parameter value or default
     */
    public function query(string $key, ?string $default = null): ?string
    {
        return $this->get[$key] ?? $default;
    }

    /**
     * Get POST parameter
     * 
     * @param string $key Parameter key
     * @param mixed $default Default value
     * @return mixed Parameter value or default
     */
    public function post(string $key, mixed $default = null): mixed
    {
        return $this->post[$key] ?? $default;
    }

    /**
     * Get uploaded file information
     * 
     * @param string $key File input name
     * @return array<string, mixed>|null File information or null
     */
    public function file(string $key): ?array
    {
        return $this->files[$key] ?? null;
    }

    /**
     * Get server variable
     * 
     * @param string $key Server variable key
     * @param string|null $default Default value
     * @return string|null Server variable or default
     */
    public function server(string $key, ?string $default = null): ?string
    {
        return $this->server[$key] ?? $default;
    }

    /**
     * Get all input data combined
     * 
     * @return array<string, mixed> All input data
     */
    public function all(): array
    {
        return array_merge($this->get, $this->post, $this->routeParameters);
    }

    /**
     * Get only specified keys
     * 
     * @param array<int, string> $keys Keys to extract
     * @return array<string, mixed> Filtered input data
     */
    public function only(array $keys): array
    {
        $data = $this->all();
        $result = [];

        foreach ($keys as $key) {
            if (isset($data[$key])) {
                $result[$key] = $data[$key];
            }
        }

        return $result;
    }

    /**
     * Get all except specified keys
     * 
     * @param array<int, string> $keys Keys to exclude
     * @return array<string, mixed> Filtered input data
     */
    public function except(array $keys): array
    {
        $data = $this->all();

        foreach ($keys as $key) {
            unset($data[$key]);
        }

        return $data;
    }

    /**
     * Check if request has specific key
     * 
     * @param string $key Parameter key
     * @return bool True if key exists
     */
    public function has(string $key): bool
    {
        return isset($this->get[$key]) || 
               isset($this->post[$key]) || 
               isset($this->routeParameters[$key]);
    }

    /**
     * Get request method
     * 
     * @return string HTTP method (uppercase)
     */
    public function method(): string
    {
        return strtoupper($this->server['REQUEST_METHOD'] ?? 'GET');
    }

    /**
     * Get request URI
     * 
     * @return string Request URI
     */
    public function uri(): string
    {
        return $this->server['REQUEST_URI'] ?? '/';
    }

    /**
     * Get request path (URI without query string)
     * 
     * @return string Request path
     */
    public function path(): string
    {
        $uri = $this->uri();
        $queryPosition = strpos($uri, '?');
        
        return $queryPosition !== false ? substr($uri, 0, $queryPosition) : $uri;
    }

    /**
     * Check if request is AJAX
     * 
     * @return bool True if AJAX request
     */
    public function ajax(): bool
    {
        return strtolower($this->server['HTTP_X_REQUESTED_WITH'] ?? '') === 'xmlhttprequest';
    }

    /**
     * Get client IP address
     * 
     * @return string Client IP address
     */
    public function ip(): string
    {
        $ipHeaders = [
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP', 
            'HTTP_CLIENT_IP',
            'REMOTE_ADDR'
        ];

        foreach ($ipHeaders as $header) {
            $ip = $this->server[$header] ?? null;
            if ($ip) {
                // Handle comma-separated IPs
                if (str_contains($ip, ',')) {
                    $ip = trim(explode(',', $ip)[0]);
                }
                return $ip;
            }
        }

        return '127.0.0.1';
    }

    /**
     * Set route parameters
     * 
     * @param array<string, string> $parameters Route parameters
     * @return self Fluent interface
     */
    public function setRouteParameters(array $parameters): self
    {
        $this->routeParameters = $parameters;
        return $this;
    }

    /**
     * Get route parameters
     * 
     * @return array<string, string> Route parameters
     */
    public function getRouteParameters(): array
    {
        return $this->routeParameters;
    }
}
