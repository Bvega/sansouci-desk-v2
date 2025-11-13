<?php

namespace App\Core;

use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Monolog\Handler\RotatingFileHandler;
use Exception;
use TypeError;
use ParseError;
use Error;
use Throwable;

/**
 * SECURITY-HARDENED ErrorHandler V2
 * Addresses XSS taint vulnerabilities and improves error handling security
 */
class ErrorHandler
{
    private Logger $logger;
    private bool $debug;
    private string $logPath;
    private array $sensitiveParams;
    private bool $displayErrors;

    public function __construct(bool $debug = false, string $logPath = 'storage/logs')
    {
        $this->debug = $debug;
        $this->logPath = $logPath;
        $this->displayErrors = $debug;
        $this->sensitiveParams = ['password', 'token', 'key', 'secret', 'auth'];
        
        $this->setupLogger();
        $this->registerHandlers();
    }

    public function setupLogger(): void
    {
        $this->logger = new Logger('sansouci_errors');
        
        // Rotating file handler for production
        $this->logger->pushHandler(
            new RotatingFileHandler(
                $this->logPath . '/errors.log',
                7, // Keep 7 days of logs
                Logger::ERROR
            )
        );
        
        // Console handler for development
        if ($this->debug) {
            $this->logger->pushHandler(
                new StreamHandler('php://stderr', Logger::DEBUG)
            );
        }
    }

    public function registerHandlers(): void
    {
        set_error_handler([$this, 'handleError']);
        set_exception_handler([$this, 'handleException']);
        register_shutdown_function([$this, 'handleShutdown']);
    }

    public function handleError($severity, $message, $file, $line): bool
    {
        // Don't handle errors that are suppressed with @
        if (!(error_reporting() & $severity)) {
            return false;
        }

        $context = [
            'severity' => $this->getSeverityName($severity),
            'file' => $this->sanitizeFilePath($file),
            'line' => $line,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'request_uri' => $_SERVER['REQUEST_URI'] ?? 'unknown'
        ];

        $this->logger->error("PHP Error: {$message}", $context);

        if ($this->displayErrors) {
            $this->renderErrorResponse($message, $context, 'PHP Error');
        }

        return true;
    }

    public function handleException(Throwable $e): void
    {
        $context = [
            'type' => get_class($e),
            'file' => $this->sanitizeFilePath($e->getFile()),
            'line' => $e->getLine(),
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'request_uri' => $_SERVER['REQUEST_URI'] ?? 'unknown'
        ];

        $this->logger->critical("Uncaught Exception: " . $e->getMessage(), $context);

        if ($this->displayErrors) {
            $this->renderErrorResponse($e->getMessage(), $context, 'Uncaught Exception');
        } else {
            $this->renderProductionError();
        }
    }

    /**
     * SECURITY FIX: Sanitized error response rendering
     * Addresses XSS taint vulnerability by properly escaping all output
     */
    private function renderErrorResponse(string $message, array $context, string $type): void
    {
        http_response_code(500);
        header('Content-Type: application/json; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        
        $response = [
            'error' => true,
            'type' => htmlspecialchars($type, ENT_QUOTES | ENT_HTML5, 'UTF-8'),
            'message' => htmlspecialchars($message, ENT_QUOTES | ENT_HTML5, 'UTF-8'),
            'timestamp' => date('Y-m-d H:i:s')
        ];

        // SECURITY FIX: Only include debug info in development and sanitize all data
        if ($this->debug) {
            $response['debug'] = [
                'file' => htmlspecialchars($context['file'] ?? '', ENT_QUOTES | ENT_HTML5, 'UTF-8'),
                'line' => (int)($context['line'] ?? 0),
                'type' => htmlspecialchars($context['type'] ?? '', ENT_QUOTES | ENT_HTML5, 'UTF-8'),
                // CRITICAL FIX: Remove trace output to prevent XSS taint
                'trace_available' => 'Use logs for detailed trace information'
            ];
        }

        // SECURITY FIX: Use safe JSON encoding with proper escaping
        echo json_encode(
            $response, 
            JSON_PRETTY_PRINT | 
            JSON_UNESCAPED_SLASHES | 
            JSON_HEX_TAG | 
            JSON_HEX_AMP | 
            JSON_HEX_APOS | 
            JSON_HEX_QUOT
        );
    }

    /**
     * SECURITY FIX: Sanitize file paths to prevent information disclosure
     */
    private function sanitizeFilePath(string $path): string
    {
        // Remove sensitive path information
        $basePath = dirname(__DIR__, 2);
        $sanitizedPath = str_replace($basePath, '[PROJECT_ROOT]', $path);
        
        // Additional sanitization
        $sanitizedPath = htmlspecialchars($sanitizedPath, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        
        return $sanitizedPath;
    }

    private function getSeverityName(int $severity): string
    {
        $severityMap = [
            E_ERROR => 'ERROR',
            E_WARNING => 'WARNING',
            E_PARSE => 'PARSE_ERROR',
            E_NOTICE => 'NOTICE',
            E_CORE_ERROR => 'CORE_ERROR',
            E_CORE_WARNING => 'CORE_WARNING',
            E_COMPILE_ERROR => 'COMPILE_ERROR',
            E_COMPILE_WARNING => 'COMPILE_WARNING',
            E_USER_ERROR => 'USER_ERROR',
            E_USER_WARNING => 'USER_WARNING',
            E_USER_NOTICE => 'USER_NOTICE',
            E_STRICT => 'STRICT',
            E_RECOVERABLE_ERROR => 'RECOVERABLE_ERROR',
            E_DEPRECATED => 'DEPRECATED',
            E_USER_DEPRECATED => 'USER_DEPRECATED'
        ];

        return $severityMap[$severity] ?? 'UNKNOWN';
    }

    public function handleShutdown(): void
    {
        $error = error_get_last();
        
        if ($error && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
            $context = [
                'type' => $this->getSeverityName($error['type']),
                'file' => $this->sanitizeFilePath($error['file']),
                'line' => $error['line'],
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ];

            $this->logger->critical("Fatal Error: " . $error['message'], $context);
            
            if ($this->displayErrors) {
                $this->renderErrorResponse($error['message'], $context, 'Fatal Error');
            } else {
                $this->renderProductionError();
            }
        }
    }

    private function renderProductionError(): void
    {
        http_response_code(500);
        header('Content-Type: application/json; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        
        $response = [
            'error' => true,
            'message' => 'Internal server error',
            'timestamp' => date('Y-m-d H:i:s'),
            'reference' => $this->generateErrorId()
        ];

        echo json_encode($response, JSON_PRETTY_PRINT);
    }

    private function generateErrorId(): string
    {
        return 'ERR_' . date('Ymd_His') . '_' . bin2hex(random_bytes(4));
    }
}
