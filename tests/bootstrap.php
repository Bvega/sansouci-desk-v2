<?php

declare(strict_types=1);

/**
 * PHPUnit Bootstrap File
 * Sets up testing environment with security and isolation
 */

// Define testing constants
define('APP_START', microtime(true));
define('APP_ENTRY', true);
define('TESTING', true);

// Set testing environment
$_ENV['APP_ENV'] = 'testing';
$_ENV['APP_DEBUG'] = 'true';
$_ENV['DB_DATABASE'] = 'sansouci_desk_test';

// Load application bootstrap
require_once __DIR__ . '/../bootstrap/app.php';

// Set up test database (in-memory SQLite for fast testing)
if (!isset($_ENV['DB_CONNECTION'])) {
    $_ENV['DB_CONNECTION'] = 'sqlite';
    $_ENV['DB_DATABASE'] = ':memory:';
}

// Create test helper functions
if (!function_exists('createTestUser')) {
    function createTestUser(array $attributes = []): array
    {
        $defaults = [
            'nombre' => 'Test User',
            'email' => 'test@example.com',
            'password' => password_hash('password123', PASSWORD_DEFAULT),
            'rol' => 'agente'
        ];
        
        return array_merge($defaults, $attributes);
    }
}

if (!function_exists('createTestTicket')) {
    function createTestTicket(array $attributes = []): array
    {
        $defaults = [
            'numero' => 'TCK-TEST-001',
            'cliente_email' => 'customer@example.com',
            'asunto' => 'Test Ticket',
            'mensaje' => 'This is a test ticket',
            'estado' => 'abierto',
            'tipo_servicio' => 'General'
        ];
        
        return array_merge($defaults, $attributes);
    }
}

echo "Test environment initialized successfully.\n";
