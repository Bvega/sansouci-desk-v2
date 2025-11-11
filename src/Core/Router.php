<?php

declare(strict_types=1);

namespace App\Core;

use Exception;

/**
 * HTTP Router
 * Handles URL routing with middleware and parameter support
 */
class Router
{
    private array $routes = [];
    private array $middlewareGroups = [];
    private Container $container;
    private array $currentGroupMiddleware = [];
    private string $currentGroupPrefix = '';
    
    public function __construct(Container $container)
    {
        $this->container = $container;
    }
    
    /**
     * Register GET route
     */
    public function get(string $uri, string|callable $action): void
    {
        $this->addRoute('GET', $uri, $action);
    }
    
    /**
     * Register POST route
     */
    public function post(string $uri, string|callable $action): void
    {
        $this->addRoute('POST', $uri, $action);
    }
    
    /**
     * Register PUT route
     */
    public function put(string $uri, string|callable $action): void
    {
        $this->addRoute('PUT', $uri, $action);
    }
    
    /**
     * Register DELETE route
     */
    public function delete(string $uri, string|callable $action): void
    {
        $this->addRoute('DELETE', $uri, $action);
    }
    
    /**
     * Register PATCH route
     */
    public function patch(string $uri, string|callable $action): void
    {
        $this->addRoute('PATCH', $uri, $action);
    }
    
    /**
     * Register route for multiple HTTP methods
     */
    public function match(array $methods, string $uri, string|callable $action): void
    {
        foreach ($methods as $method) {
            $this->addRoute(strtoupper($method), $uri, $action);
        }
    }
    
    /**
     * Register route group with shared attributes
     */
    public function group(array $attributes, callable $callback): void
    {
        $previousMiddleware = $this->currentGroupMiddleware;
        $previousPrefix = $this->currentGroupPrefix;
        
        // Apply group middleware
        if (isset($attributes['middleware'])) {
            $middleware = is_array($attributes['middleware']) 
                ? $attributes['middleware'] 
                : [$attributes['middleware']];
            $this->currentGroupMiddleware = array_merge($this->currentGroupMiddleware, $middleware);
        }
        
        // Apply group prefix
        if (isset($attributes['prefix'])) {
            $this->currentGroupPrefix = rtrim($this->currentGroupPrefix . '/' . ltrim($attributes['prefix'], '/'), '/');
        }
        
        // Execute callback to register routes
        $callback($this);
        
        // Restore previous group settings
        $this->currentGroupMiddleware = $previousMiddleware;
        $this->currentGroupPrefix = $previousPrefix;
    }
    
    /**
     * Add route to routing table
     */
    private function addRoute(string $method, string $uri, string|callable $action): void
    {
        // Apply group prefix
        $uri = rtrim($this->currentGroupPrefix . '/' . ltrim($uri, '/'), '/') ?: '/';
        
        // Convert route parameters to regex
        $pattern = $this->convertToPattern($uri);
        
        $this->routes[] = [
            'method' => $method,
            'uri' => $uri,
            'pattern' => $pattern,
            'action' => $action,
            'middleware' => $this->currentGroupMiddleware
        ];
    }
    
    /**
     * Convert route URI to regex pattern
     */
    private function convertToPattern(string $uri): string
    {
        // Escape forward slashes
        $pattern = str_replace('/', '\/', $uri);
        
        // Convert {parameter} to named regex groups
        $pattern = preg_replace('/\{([a-zA-Z0-9_]+)\}/', '(?P<$1>[^\/]+)', $pattern);
        
        // Convert {parameter?} to optional named regex groups
        $pattern = preg_replace('/\{([a-zA-Z0-9_]+)\?\}/', '(?P<$1>[^\/]*)', $pattern);
        
        return '/^' . $pattern . '$/';
    }
    
    /**
     * Dispatch incoming request
     */
    public function dispatch(Request $request): mixed
    {
        $method = $request->getMethod();
        $uri = $request->getUri();
        
        // Find matching route
        foreach ($this->routes as $route) {
            if ($route['method'] !== $method) {
                continue;
            }
            
            if (preg_match($route['pattern'], $uri, $matches)) {
                // Extract route parameters
                $parameters = $this->extractParameters($matches);
                
                // Apply route middleware
                return $this->executeRoute($route, $request, $parameters);
            }
        }
        
        // No route found - 404
        throw new Exception('Route not found', 404);
    }
    
    /**
     * Extract route parameters from regex matches
     */
    private function extractParameters(array $matches): array
    {
        $parameters = [];
        
        foreach ($matches as $key => $value) {
            if (!is_numeric($key)) {
                $parameters[$key] = $value;
            }
        }
        
        return $parameters;
    }
    
    /**
     * Execute route with middleware
     */
    private function executeRoute(array $route, Request $request, array $parameters): mixed
    {
        // Set route parameters in request
        $request->setRouteParameters($parameters);
        
        // Apply route middleware
        $middleware = $route['middleware'] ?? [];
        
        // Build middleware chain
        $next = function($request) use ($route, $parameters) {
            return $this->callAction($route['action'], $request, $parameters);
        };
        
        // Apply middleware in reverse order
        foreach (array_reverse($middleware) as $middlewareName) {
            $middlewareInstance = $this->resolveMiddleware($middlewareName);
            
            $next = function($request) use ($middlewareInstance, $next) {
                return $middlewareInstance->handle($request, $next);
            };
        }
        
        return $next($request);
    }
    
    /**
     * Call route action
     */
    private function callAction(string|callable $action, Request $request, array $parameters): mixed
    {
        if (is_callable($action)) {
            return $action($request, ...$parameters);
        }
        
        // Parse Controller@method syntax
        if (str_contains($action, '@')) {
            [$controller, $method] = explode('@', $action, 2);
            
            // Resolve controller from container
            $controllerClass = 'App\\Controllers\\' . $controller;
            
            if (!class_exists($controllerClass)) {
                throw new Exception("Controller not found: {$controllerClass}");
            }
            
            $controllerInstance = $this->container->get($controllerClass);
            
            if (!method_exists($controllerInstance, $method)) {
                throw new Exception("Method {$method} not found in {$controllerClass}");
            }
            
            // Call controller method
            return $controllerInstance->$method($request, ...$parameters);
        }
        
        throw new Exception("Invalid route action: {$action}");
    }
    
    /**
     * Resolve middleware instance
     */
    private function resolveMiddleware(string $middleware): object
    {
        // Check if it's a middleware group
        if (isset($this->middlewareGroups[$middleware])) {
            throw new Exception("Middleware groups not implemented yet: {$middleware}");
        }
        
        // Built-in middleware
        $middlewareMap = [
            'auth' => 'App\\Middleware\\AuthMiddleware',
            'guest' => 'App\\Middleware\\GuestMiddleware', 
            'role' => 'App\\Middleware\\RoleMiddleware',
            'throttle' => 'App\\Middleware\\ThrottleMiddleware',
            'cors' => 'App\\Middleware\\CorsMiddleware'
        ];
        
        if (isset($middlewareMap[$middleware])) {
            $middleware = $middlewareMap[$middleware];
        }
        
        // Check if middleware includes parameters (e.g., 'role:admin')
        if (str_contains($middleware, ':')) {
            [$middleware, $parameters] = explode(':', $middleware, 2);
            $middlewareClass = $middlewareMap[$middleware] ?? $middleware;
            
            if (!class_exists($middlewareClass)) {
                throw new Exception("Middleware not found: {$middlewareClass}");
            }
            
            $instance = $this->container->get($middlewareClass);
            
            // Set middleware parameters
            if (method_exists($instance, 'setParameters')) {
                $instance->setParameters(explode(',', $parameters));
            }
            
            return $instance;
        }
        
        if (!class_exists($middleware)) {
            throw new Exception("Middleware not found: {$middleware}");
        }
        
        return $this->container->get($middleware);
    }
    
    /**
     * Register middleware group
     */
    public function middlewareGroup(string $name, array $middleware): void
    {
        $this->middlewareGroups[$name] = $middleware;
    }
    
    /**
     * Get all registered routes
     */
    public function getRoutes(): array
    {
        return $this->routes;
    }
    
    /**
     * Generate URL for named route
     */
    public function url(string $name, array $parameters = []): string
    {
        // Implementation for named routes would go here
        // For now, return a basic URL
        return env('APP_URL') . $name;
    }
}
