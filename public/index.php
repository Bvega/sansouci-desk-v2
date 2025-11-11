<?php

declare(strict_types=1);

/**
 * Sansouci-Desk V2.0 Entry Point
 * Security-hardened web application entry
 */

try {
    // Load the app
    $app = require_once __DIR__ . '/../bootstrap/app.php';
    
    // Handle the request and show the response
    echo $app->handleRequest();
    
} catch (Exception $e) {
    // Secure error handling
    if (getenv('APP_DEBUG') === 'true') {
        echo "<h1>Error:</h1><p>" . htmlspecialchars($e->getMessage()) . "</p>";
    } else {
        echo "<h1>Service temporarily unavailable</h1>";
    }
}
