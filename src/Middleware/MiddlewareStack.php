<?php

declare(strict_types=1);

namespace App\Middleware;

use App\Core\Request;
use Exception;

/**
 * Middleware Stack Handler
 * Manages middleware execution chain with proper error handling
 */
class MiddlewareStack
{
    private array $middleware = [];
    
    /**
     * Add middleware to stack
     */
    public function add(string $name, callable $middleware): void
    {
        $this->middleware[$name] = $middleware;
    }
    
    /**
     * Handle request through middleware stack
     */
    public function handle(Request $request, callable $next): mixed
    {
        // If no middleware, just execute next
        if (empty($this->middleware)) {
            return $next($request);
        }
        
        // Build middleware chain
        $chain = $this->buildChain($next);
        
        // Execute the chain
        return $chain($request);
    }
    
    /**
     * Build middleware execution chain
     */
    private function buildChain(callable $final): callable
    {
        $chain = $final;
        
        // Build chain in reverse order
        foreach (array_reverse($this->middleware) as $middleware) {
            $chain = function(Request $request) use ($middleware, $chain) {
                return $middleware($request, $chain);
            };
        }
        
        return $chain;
    }
    
    /**
     * Get all registered middleware
     */
    public function getMiddleware(): array
    {
        return $this->middleware;
    }
    
    /**
     * Remove middleware from stack
     */
    public function remove(string $name): void
    {
        unset($this->middleware[$name]);
    }
    
    /**
     * Check if middleware exists
     */
    public function has(string $name): bool
    {
        return isset($this->middleware[$name]);
    }
}

/**
 * Base Middleware Interface
 */
interface MiddlewareInterface
{
    public function handle(Request $request, callable $next): mixed;
}

/**
 * Authentication Middleware
 */
class AuthMiddleware implements MiddlewareInterface
{
    public function handle(Request $request, callable $next): mixed
    {
        // Check if user is authenticated
        if (!isset($_SESSION['user'])) {
            // Log authentication attempt
            log_security_event('unauthenticated_access', [
                'uri' => $request->getUri(),
                'method' => $request->getMethod()
            ]);
            
            if ($request->wantsJson()) {
                http_response_code(401);
                header('Content-Type: application/json');
                echo json_encode(['error' => 'Authentication required']);
                exit;
            }
            
            secure_redirect('/login');
        }
        
        // Validate session integrity
        $auth = app('auth');
        if (!$auth->validateSession()) {
            session_destroy();
            secure_redirect('/login');
        }
        
        return $next($request);
    }
}

/**
 * Guest Middleware (redirect authenticated users)
 */
class GuestMiddleware implements MiddlewareInterface
{
    public function handle(Request $request, callable $next): mixed
    {
        if (isset($_SESSION['user'])) {
            secure_redirect('/dashboard');
        }
        
        return $next($request);
    }
}

/**
 * Role-based Access Middleware
 */
class RoleMiddleware implements MiddlewareInterface
{
    private array $allowedRoles = [];
    
    public function setParameters(array $roles): void
    {
        $this->allowedRoles = $roles;
    }
    
    public function handle(Request $request, callable $next): mixed
    {
        if (!isset($_SESSION['user'])) {
            throw new Exception('Authentication required', 401);
        }
        
        $userRole = $_SESSION['user']['rol'] ?? 'guest';
        
        if (!in_array($userRole, $this->allowedRoles)) {
            log_security_event('unauthorized_role_access', [
                'user_id' => $_SESSION['user']['id'],
                'user_role' => $userRole,
                'required_roles' => $this->allowedRoles,
                'uri' => $request->getUri()
            ]);
            
            if ($request->wantsJson()) {
                http_response_code(403);
                header('Content-Type: application/json');
                echo json_encode(['error' => 'Access denied']);
                exit;
            }
            
            throw new Exception('Access denied', 403);
        }
        
        return $next($request);
    }
}

/**
 * Rate Limiting Middleware
 */
class ThrottleMiddleware implements MiddlewareInterface
{
    private int $maxAttempts = 60;
    private int $timeWindow = 3600; // 1 hour
    
    public function setParameters(array $params): void
    {
        if (count($params) >= 1) {
            $this->maxAttempts = (int) $params[0];
        }
        if (count($params) >= 2) {
            $this->timeWindow = (int) $params[1];
        }
    }
    
    public function handle(Request $request, callable $next): mixed
    {
        $key = $this->getThrottleKey($request);
        
        if (!rate_limit_check($key, $this->maxAttempts, $this->timeWindow)) {
            log_security_event('rate_limit_exceeded', [
                'key' => $key,
                'max_attempts' => $this->maxAttempts,
                'time_window' => $this->timeWindow,
                'uri' => $request->getUri()
            ]);
            
            if ($request->wantsJson()) {
                http_response_code(429);
                header('Content-Type: application/json');
                echo json_encode([
                    'error' => 'Too many requests',
                    'retry_after' => $this->timeWindow
                ]);
                exit;
            }
            
            http_response_code(429);
            echo 'Too many requests. Please try again later.';
            exit;
        }
        
        return $next($request);
    }
    
    private function getThrottleKey(Request $request): string
    {
        $ip = $request->ip();
        $uri = $request->getUri();
        
        // Include user ID if authenticated
        $userId = $_SESSION['user']['id'] ?? 'guest';
        
        return "throttle:{$ip}:{$userId}:{$uri}";
    }
}

/**
 * CORS Middleware
 */
class CorsMiddleware implements MiddlewareInterface
{
    public function handle(Request $request, callable $next): mixed
    {
        $origin = $request->header('Origin');
        $allowedOrigins = config('cors.allowed_origins', ['localhost']);
        
        if ($origin && in_array($origin, $allowedOrigins)) {
            header("Access-Control-Allow-Origin: {$origin}");
        }
        
        header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, Authorization, X-CSRF-Token');
        header('Access-Control-Allow-Credentials: true');
        header('Access-Control-Max-Age: 86400'); // 24 hours
        
        // Handle preflight OPTIONS request
        if ($request->getMethod() === 'OPTIONS') {
            http_response_code(200);
            exit;
        }
        
        return $next($request);
    }
}

/**
 * Security Headers Middleware
 */
class SecurityHeadersMiddleware implements MiddlewareInterface
{
    public function handle(Request $request, callable $next): mixed
    {
        // Security headers are handled by SecurityManager
        $security = app('security');
        $security->setSecurityHeaders();
        
        return $next($request);
    }
}

/**
 * Request Logging Middleware
 */
class LoggingMiddleware implements MiddlewareInterface
{
    public function handle(Request $request, callable $next): mixed
    {
        $startTime = microtime(true);
        
        // Execute request
        $response = $next($request);
        
        $executionTime = microtime(true) - $startTime;
        
        // Log request
        $logger = app('logger');
        $logger->info('HTTP Request', [
            'method' => $request->getMethod(),
            'uri' => $request->getUri(),
            'ip' => $request->ip(),
            'user_agent' => $request->userAgent(),
            'user_id' => $_SESSION['user']['id'] ?? null,
            'execution_time' => $executionTime,
            'memory_usage' => memory_get_peak_usage(true)
        ]);
        
        return $response;
    }
}

/**
 * Input Sanitization Middleware
 */
class SanitizeInputMiddleware implements MiddlewareInterface
{
    public function handle(Request $request, callable $next): mixed
    {
        // Sanitize input data
        $security = app('security');
        
        // Sanitize GET parameters
        $_GET = $security->sanitizeInput($_GET);
        
        // Sanitize POST parameters  
        $_POST = $security->sanitizeInput($_POST);
        
        return $next($request);
    }
}

/**
 * CSRF Verification Middleware
 */
class VerifyCsrfTokenMiddleware implements MiddlewareInterface
{
    private array $excludedRoutes = [
        '/api/webhook',
        '/api/callback'
    ];
    
    public function handle(Request $request, callable $next): mixed
    {
        // Skip CSRF for safe methods
        if (in_array($request->getMethod(), ['GET', 'HEAD', 'OPTIONS'])) {
            return $next($request);
        }
        
        // Skip CSRF for excluded routes
        $uri = $request->getUri();
        foreach ($this->excludedRoutes as $route) {
            if (str_starts_with($uri, $route)) {
                return $next($request);
            }
        }
        
        // Verify CSRF token
        if (!$request->verifyCsrfToken()) {
            log_security_event('csrf_token_mismatch', [
                'uri' => $uri,
                'method' => $request->getMethod(),
                'token_provided' => !empty($request->csrfToken())
            ]);
            
            if ($request->wantsJson()) {
                http_response_code(419);
                header('Content-Type: application/json');
                echo json_encode(['error' => 'CSRF token mismatch']);
                exit;
            }
            
            throw new Exception('CSRF token mismatch', 419);
        }
        
        return $next($request);
    }
}
