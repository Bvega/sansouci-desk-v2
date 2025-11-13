<?php

declare(strict_types=1);

namespace App\Core;

use App\Security\SecurityManager;
use Monolog\Logger;
use Throwable;

/**
 * Application Error Handler
 * Secure error handling with proper logging and user-safe responses
 */
class ErrorHandler
{
    private Logger $logger;
    private SecurityManager $security;
    private bool $debug;
    
    public function __construct(Logger $logger, SecurityManager $security)
    {
        $this->logger = $logger;
        $this->security = $security;
        $this->debug = env('APP_DEBUG', false);
    }
    
    /**
     * Register error and exception handlers
     */
    public function register(): void
    {
        // Set error reporting based on environment
        if ($this->debug) {
            error_reporting(E_ALL);
            ini_set('display_errors', '1');
        } else {
            error_reporting(0);
            ini_set('display_errors', '0');
        }
        
        // Register custom handlers
        set_error_handler([$this, 'handleError']);
        set_exception_handler([$this, 'handleException']);
        register_shutdown_function([$this, 'handleShutdown']);
    }
    
    /**
     * Handle PHP errors
     */
    public function handleError(int $level, string $message, string $file = '', int $line = 0): bool
    {
        // Ignore suppressed errors (@)
        if (!(error_reporting() & $level)) {
            return false;
        }
        
        $errorTypes = [
            E_ERROR => 'ERROR',
            E_WARNING => 'WARNING',
            E_PARSE => 'PARSE',
            E_NOTICE => 'NOTICE',
            E_CORE_ERROR => 'CORE_ERROR',
            E_CORE_WARNING => 'CORE_WARNING',
            E_USER_ERROR => 'USER_ERROR',
            E_USER_WARNING => 'USER_WARNING',
            E_USER_NOTICE => 'USER_NOTICE',
            E_STRICT => 'STRICT',
            E_RECOVERABLE_ERROR => 'RECOVERABLE_ERROR',
            E_DEPRECATED => 'DEPRECATED',
            E_USER_DEPRECATED => 'USER_DEPRECATED'
        ];
        
        $errorType = $errorTypes[$level] ?? 'UNKNOWN';
        
        // Log the error
        $this->logger->error("PHP {$errorType}: {$message}", [
            'file' => $file,
            'line' => $line,
            'level' => $level,
            'trace' => debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 10)
        ]);
        
        // Convert errors to exceptions for fatal errors
        if (in_array($level, [E_ERROR, E_PARSE, E_CORE_ERROR, E_USER_ERROR, E_RECOVERABLE_ERROR])) {
            throw new \ErrorException($message, 0, $level, $file, $line);
        }
        
        return true; // Don't execute PHP internal error handler
    }
    
    /**
     * Handle uncaught exceptions
     */
    public function handleException(Throwable $e): void
    {
        try {
            // Log the exception with full context
            $this->logException($e);
            
            // Check if this is a security-related exception
            if ($this->isSecurityException($e)) {
                $this->security->logSecurityEvent('security_exception', [
                    'exception' => get_class($e),
                    'message' => $e->getMessage(),
                    'file' => $e->getFile(),
                    'line' => $e->getLine()
                ]);
            }
            
            // Send appropriate response
            $this->sendErrorResponse($e);
            
        } catch (Throwable $loggingException) {
            // Fallback if logging fails
            $this->emergencyResponse($e, $loggingException);
        }
    }
    
    /**
     * Handle fatal errors during shutdown
     */
    public function handleShutdown(): void
    {
        $error = error_get_last();
        
        if ($error !== null && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
            $this->logger->critical('Fatal Error', [
                'message' => $error['message'],
                'file' => $error['file'],
                'line' => $error['line'],
                'type' => $error['type']
            ]);
            
            // Send error response if not already sent
            if (!headers_sent()) {
                $this->sendFatalErrorResponse();
            }
        }
    }
    
    /**
     * Log exception with context
     */
    private function logException(Throwable $e): void
    {
        $context = [
            'exception' => get_class($e),
            'message' => $e->getMessage(),
            'file' => $e->getFile(),
            'line' => $e->getLine(),
            'code' => $e->getCode(),
            'trace' => $this->getCleanTrace($e),
            'previous' => $e->getPrevious() ? [
                'exception' => get_class($e->getPrevious()),
                'message' => $e->getPrevious()->getMessage(),
                'file' => $e->getPrevious()->getFile(),
                'line' => $e->getPrevious()->getLine()
            ] : null
        ];
        
        // Add request context if available
        if (isset($_SERVER['REQUEST_METHOD'])) {
            $context['request'] = [
                'method' => $_SERVER['REQUEST_METHOD'],
                'uri' => $_SERVER['REQUEST_URI'] ?? '',
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
            ];
        }
        
        // Add user context if logged in
        if (isset($_SESSION['user'])) {
            $context['user'] = [
                'id' => $_SESSION['user']['id'],
                'email' => $_SESSION['user']['email']
            ];
        }
        
        // Log with appropriate level
        $level = $this->getLogLevel($e);
        $this->logger->log($level, $e->getMessage(), $context);
    }
    
    /**
     * Get clean stack trace without sensitive data
     */
    private function getCleanTrace(Throwable $e): array
    {
        $trace = $e->getTrace();
        $cleanTrace = [];
        
        foreach ($trace as $frame) {
            $cleanFrame = [
                'file' => $frame['file'] ?? 'unknown',
                'line' => $frame['line'] ?? 0,
                'function' => $frame['function'] ?? 'unknown'
            ];
            
            if (isset($frame['class'])) {
                $cleanFrame['class'] = $frame['class'];
            }
            
            if (isset($frame['type'])) {
                $cleanFrame['type'] = $frame['type'];
            }
            
            // Don't include sensitive function arguments
            $cleanTrace[] = $cleanFrame;
        }
        
        return $cleanTrace;
    }
    
    /**
     * Get appropriate log level for exception
     */
    private function getLogLevel(Throwable $e): string
    {
        return match (true) {
            $e instanceof \Error => 'critical',
            $e instanceof \ParseError => 'critical',
            $e instanceof \TypeError => 'error',
            $e instanceof \InvalidArgumentException => 'error',
            $this->isSecurityException($e) => 'alert',
            default => 'error'
        };
    }
    
    /**
     * Check if exception is security-related
     */
    private function isSecurityException(Throwable $e): bool
    {
        $securityPatterns = [
            'csrf',
            'unauthorized',
            'forbidden',
            'injection',
            'xss',
            'security',
            'authentication',
            'authorization'
        ];
        
        $message = strtolower($e->getMessage());
        
        foreach ($securityPatterns as $pattern) {
            if (str_contains($message, $pattern)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Send error response to client
     */
    private function sendErrorResponse(Throwable $e): void
    {
        if (headers_sent()) {
            return;
        }
        
        // Determine response format
        $isAjax = isset($_SERVER['HTTP_X_REQUESTED_WITH']) 
               && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
        
        $acceptsJson = isset($_SERVER['HTTP_ACCEPT']) 
                    && str_contains($_SERVER['HTTP_ACCEPT'], 'application/json');
        
        // Set appropriate HTTP status code
        $statusCode = $this->getHttpStatusCode($e);
        http_response_code($statusCode);
        
        if ($isAjax || $acceptsJson) {
            $this->sendJsonErrorResponse($e, $statusCode);
        } else {
            $this->sendHtmlErrorResponse($e, $statusCode);
        }
    }
    
    /**
     * Get HTTP status code for exception
     */
    private function getHttpStatusCode(Throwable $e): int
    {
        return match (true) {
            $e->getCode() === 404 => 404,
            $e->getCode() === 403 => 403,
            $e->getCode() === 401 => 401,
            $e->getCode() === 400 => 400,
            str_contains(strtolower($e->getMessage()), 'unauthorized') => 401,
            str_contains(strtolower($e->getMessage()), 'forbidden') => 403,
            str_contains(strtolower($e->getMessage()), 'not found') => 404,
            default => 500
        };
    }
    
    /**
     * Send JSON error response
     */
    private function sendJsonErrorResponse(Throwable $e, int $statusCode): void
    {
        header('Content-Type: application/json');
        
        $response = [
            'error' => true,
            'message' => $this->getUserFriendlyMessage($e, $statusCode)
        ];
        
        if ($this->debug) {
            $response['debug'] = [
                'exception' => get_class($e),
                'message' => $e->getMessage(),
                'file' => $e->getFile(),
                'line' => $e->getLine(),
                'trace' => $e->getTraceAsString()
            ];
        }
        
        echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }
    
    /**
     * Send HTML error response
     */
    private function sendHtmlErrorResponse(Throwable $e, int $statusCode): void
    {
        header('Content-Type: text/html; charset=utf-8');
        
        $title = $this->getErrorTitle($statusCode);
        $message = $this->getUserFriendlyMessage($e, $statusCode);
        
        $debug = $this->debug ? $this->getDebugOutput($e) : '';
        
        echo $this->renderErrorPage($title, $message, $statusCode, $debug);
    }
    
    /**
     * Send fatal error response
     */
    private function sendFatalErrorResponse(): void
    {
        http_response_code(500);
        header('Content-Type: text/html; charset=utf-8');
        
        echo $this->renderErrorPage(
            'Server Error',
            'A fatal error occurred and the request could not be completed.',
            500
        );
    }
    
    /**
     * Get user-friendly error message
     */
    private function getUserFriendlyMessage(Throwable $e, int $statusCode): string
    {
        if (!$this->debug) {
            return match ($statusCode) {
                400 => 'Bad Request',
                401 => 'Authentication Required',
                403 => 'Access Denied',
                404 => 'Page Not Found',
                405 => 'Method Not Allowed',
                429 => 'Too Many Requests',
                500 => 'Internal Server Error',
                503 => 'Service Unavailable',
                default => 'An error occurred'
            };
        }
        
        return $e->getMessage();
    }
    
    /**
     * Get error page title
     */
    private function getErrorTitle(int $statusCode): string
    {
        return match ($statusCode) {
            400 => 'Bad Request',
            401 => 'Unauthorized',
            403 => 'Forbidden',
            404 => 'Not Found',
            405 => 'Method Not Allowed',
            429 => 'Rate Limited',
            500 => 'Server Error',
            503 => 'Service Unavailable',
            default => 'Error'
        };
    }
    
    /**
     * Get debug output for development
     */
    private function getDebugOutput(Throwable $e): string
    {
        return sprintf(
            '<div class="debug"><h3>Debug Information</h3><p><strong>Exception:</strong> %s</p><p><strong>Message:</strong> %s</p><p><strong>File:</strong> %s:%d</p><pre>%s</pre></div>',
            htmlspecialchars(get_class($e)),
            htmlspecialchars($e->getMessage()),
            htmlspecialchars($e->getFile()),
            $e->getLine(),
            htmlspecialchars($e->getTraceAsString())
        );
    }
    
    /**
     * Render error page HTML
     */
    private function renderErrorPage(string $title, string $message, int $code, string $debug = ''): string
    {
        return sprintf(
            '<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>%s - Sansouci Desk</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 600px; margin: 100px auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; margin-bottom: 20px; }
        .error-code { color: #666; font-size: 18px; margin-bottom: 10px; }
        .message { color: #555; line-height: 1.6; margin-bottom: 30px; }
        .debug { background: #f8f8f8; padding: 20px; border-radius: 4px; margin-top: 30px; border-left: 4px solid #ff6b6b; }
        .debug h3 { margin-top: 0; color: #d63031; }
        .debug pre { overflow-x: auto; background: #fff; padding: 15px; border-radius: 4px; }
        a { color: #0066cc; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <div class="error-code">Error %d</div>
        <h1>%s</h1>
        <div class="message">%s</div>
        <p><a href="/">← Return to Home</a></p>
        %s
    </div>
</body>
</html>',
            htmlspecialchars($title),
            $code,
            htmlspecialchars($title),
            htmlspecialchars($message),
            $debug
        );
    }
    
    /**
     * Emergency response when everything fails
     */
    private function emergencyResponse(Throwable $original, Throwable $loggingException): void
    {
        if (!headers_sent()) {
            http_response_code(500);
            header('Content-Type: text/plain');
        }
        
        if ($this->debug) {
            echo "EMERGENCY ERROR:\n\n";
            echo "Original Exception: " . $original->getMessage() . "\n";
            echo "Logging Exception: " . $loggingException->getMessage() . "\n";
        } else {
            echo "A critical error occurred. Please contact support.";
        }
        
        exit(1);
    }
}
