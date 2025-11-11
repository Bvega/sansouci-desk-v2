<?php

declare(strict_types=1);

namespace App\Core;

use App\Security\SecurityManager;
use App\Middleware\MiddlewareStack;
use Exception;

/**
 * Main Application Class
 * Handles request routing, middleware, and application lifecycle
 */
class Application
{
    private Container $container;
    private Router $router;
    private MiddlewareStack $middleware;
    private SecurityManager $security;
    
    public function __construct(Container $container)
    {
        $this->container = $container;
        $this->router = new Router($container);
        $this->middleware = new MiddlewareStack();
        $this->security = $container->get('security');
        
        $this->registerCoreMiddleware();
    }
    
    /**
     * Register core security middleware
     */
    private function registerCoreMiddleware(): void
    {
        // Security headers middleware (applied to all requests)
        $this->middleware->add('security_headers', function($request, $next) {
            $this->security->setSecurityHeaders();
            return $next($request);
        });
        
        // CSRF protection middleware (applied to POST/PUT/DELETE requests)
        $this->middleware->add('csrf_protection', function($request, $next) {
            if (in_array($_SERVER['REQUEST_METHOD'], ['POST', 'PUT', 'DELETE', 'PATCH'])) {
                $token = $_POST['_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
                
                if (!verify_csrf_token($token)) {
                    log_security_event('csrf_token_mismatch', [
                        'uri' => $_SERVER['REQUEST_URI'] ?? '',
                        'method' => $_SERVER['REQUEST_METHOD'] ?? ''
                    ]);
                    
                    http_response_code(403);
                    die('Security error: Invalid CSRF token');
                }
            }
            return $next($request);
        });
        
        // Rate limiting middleware
        $this->middleware->add('rate_limiting', function($request, $next) {
            if (config('security.rate_limit_enabled', true)) {
                $key = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
                $maxAttempts = config('security.rate_limit_requests', 100);
                $timeWindow = config('security.rate_limit_window', 3600);
                
                if (!rate_limit_check($key, $maxAttempts, $timeWindow)) {
                    http_response_code(429);
                    die('Too many requests. Please try again later.');
                }
            }
            return $next($request);
        });
    }
    
    /**
     * Handle incoming HTTP request
     */
    public function handleRequest(): void
    {
        try {
            $request = $this->createRequestFromGlobals();
            
            // Apply middleware stack
            $response = $this->middleware->handle($request, function($request) {
                return $this->router->dispatch($request);
            });
            
            $this->sendResponse($response);
            
        } catch (Exception $e) {
            $this->handleException($e);
        }
    }
    
    /**
     * Create request object from PHP globals
     */
    private function createRequestFromGlobals(): Request
    {
        return new Request(
            $_GET,
            $_POST,
            $_FILES,
            $_SERVER,
            getallheaders() ?: []
        );
    }
    
    /**
     * Send HTTP response
     */
    private function sendResponse($response): void
    {
        if (is_string($response)) {
            echo $response;
        } elseif (is_array($response) || is_object($response)) {
            header('Content-Type: application/json');
            echo json_encode($response);
        } else {
            echo $response;
        }
    }
    
    /**
     * Handle application exceptions securely
     */
    private function handleException(Exception $e): void
    {
        $logger = $this->container->get('logger');
        
        // Log the full exception details
        $logger->error('Application Exception', [
            'exception' => get_class($e),
            'message' => $e->getMessage(),
            'file' => $e->getFile(),
            'line' => $e->getLine(),
            'trace' => $e->getTraceAsString()
        ]);
        
        // Show user-friendly error message without exposing internals
        http_response_code(500);
        
        if (env('APP_DEBUG', false)) {
            echo "Error: " . $e->getMessage() . "\n";
            echo "File: " . $e->getFile() . " Line: " . $e->getLine();
        } else {
            echo "Internal server error. Please contact support if the problem persists.";
        }
    }
    
    /**
     * Register routes for the application
     */
    public function registerRoutes(): void
    {
        // Authentication routes
        $this->router->get('/', 'HomeController@index');
        $this->router->get('/login', 'AuthController@showLogin');
        $this->router->post('/login', 'AuthController@login');
        $this->router->post('/logout', 'AuthController@logout');
        
        // Ticket management routes (require authentication)
        $this->router->group(['middleware' => 'auth'], function($router) {
            $router->get('/dashboard', 'DashboardController@index');
            $router->get('/tickets', 'TicketController@index');
            $router->get('/tickets/create', 'TicketController@create');
            $router->post('/tickets', 'TicketController@store');
            $router->get('/tickets/{id}', 'TicketController@show');
            $router->put('/tickets/{id}', 'TicketController@update');
            $router->delete('/tickets/{id}', 'TicketController@destroy');
        });
        
        // User management routes (require admin role)
        $this->router->group(['middleware' => ['auth', 'role:admin']], function($router) {
            $router->get('/users', 'UserController@index');
            $router->get('/users/create', 'UserController@create');
            $router->post('/users', 'UserController@store');
            $router->get('/users/{id}/edit', 'UserController@edit');
            $router->put('/users/{id}', 'UserController@update');
            $router->delete('/users/{id}', 'UserController@destroy');
        });
        
        // Settings routes (require admin role)
        $this->router->group(['middleware' => ['auth', 'role:admin']], function($router) {
            $router->get('/settings/email', 'SettingsController@email');
            $router->post('/settings/email', 'SettingsController@updateEmail');
            $router->get('/settings/security', 'SettingsController@security');
            $router->post('/settings/security', 'SettingsController@updateSecurity');
        });
        
        // API routes
        $this->router->group(['prefix' => 'api/v1'], function($router) {
            $router->post('/tickets', 'Api\\TicketController@store');
            $router->get('/tickets/{id}/status', 'Api\\TicketController@status');
        });
    }
    
    /**
     * Get container instance
     */
    public function getContainer(): Container
    {
        return $this->container;
    }
}
