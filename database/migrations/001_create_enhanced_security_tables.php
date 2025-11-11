<?php

/**
 * Database Migration: Enhanced Security Tables
 * Creates modernized table structure with proper indexing and security controls
 * 
 * Run this migration after setting up the basic tables from the original system
 */

declare(strict_types=1);

class CreateEnhancedSecurityTables
{
    /**
     * Run the migration
     */
    public function up(): void
    {
        $sql = [
            // Enhanced users table with security columns
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS 
                password_changed_at TIMESTAMP NULL DEFAULT NULL,
                failed_login_attempts INT DEFAULT 0,
                locked_until TIMESTAMP NULL DEFAULT NULL,
                last_login_at TIMESTAMP NULL DEFAULT NULL,
                last_login_ip VARCHAR(45) NULL DEFAULT NULL,
                mfa_secret VARCHAR(255) NULL DEFAULT NULL,
                mfa_enabled TINYINT(1) DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP",
                
            // Security events log table
            "CREATE TABLE IF NOT EXISTS security_events (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                event_type VARCHAR(100) NOT NULL,
                event_data JSON NULL,
                user_id INT UNSIGNED NULL,
                ip_address VARCHAR(45) NOT NULL,
                user_agent TEXT NULL,
                session_id VARCHAR(255) NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_event_type (event_type),
                INDEX idx_user_id (user_id),
                INDEX idx_ip_address (ip_address),
                INDEX idx_created_at (created_at),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )",
            
            // Audit trail table
            "CREATE TABLE IF NOT EXISTS audit_logs (
                id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                user_id INT UNSIGNED NULL,
                action VARCHAR(100) NOT NULL,
                table_name VARCHAR(100) NULL,
                record_id INT UNSIGNED NULL,
                old_values JSON NULL,
                new_values JSON NULL,
                ip_address VARCHAR(45) NOT NULL,
                user_agent TEXT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_user_id (user_id),
                INDEX idx_action (action),
                INDEX idx_table_record (table_name, record_id),
                INDEX idx_created_at (created_at),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )",
            
            // Session management table
            "CREATE TABLE IF NOT EXISTS sessions (
                id VARCHAR(255) PRIMARY KEY,
                user_id INT UNSIGNED NULL,
                ip_address VARCHAR(45) NULL,
                user_agent TEXT NULL,
                payload TEXT NOT NULL,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_user_id (user_id),
                INDEX idx_last_activity (last_activity),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )",
            
            // Rate limiting table
            "CREATE TABLE IF NOT EXISTS rate_limits (
                id VARCHAR(255) PRIMARY KEY,
                attempts INT DEFAULT 1,
                reset_time TIMESTAMP NOT NULL,
                INDEX idx_reset_time (reset_time)
            )",
            
            // Enhanced configuration table
            "CREATE TABLE IF NOT EXISTS system_config (
                id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                config_key VARCHAR(100) NOT NULL UNIQUE,
                config_value TEXT NULL,
                is_sensitive TINYINT(1) DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_config_key (config_key)
            )",
            
            // Password reset tokens table
            "CREATE TABLE IF NOT EXISTS password_reset_tokens (
                email VARCHAR(255) NOT NULL,
                token VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                INDEX idx_email (email),
                INDEX idx_token (token),
                INDEX idx_expires_at (expires_at)
            )",
            
            // Enhanced tickets table with better security
            "ALTER TABLE tickets ADD COLUMN IF NOT EXISTS 
                priority ENUM('low', 'medium', 'high', 'urgent') DEFAULT 'medium',
                estimated_resolution TIMESTAMP NULL DEFAULT NULL,
                resolution_notes TEXT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP",
                
            // File uploads table for secure file management
            "CREATE TABLE IF NOT EXISTS file_uploads (
                id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                ticket_id INT UNSIGNED NOT NULL,
                original_name VARCHAR(255) NOT NULL,
                stored_name VARCHAR(255) NOT NULL,
                file_path VARCHAR(500) NOT NULL,
                mime_type VARCHAR(100) NOT NULL,
                file_size INT UNSIGNED NOT NULL,
                uploaded_by INT UNSIGNED NOT NULL,
                is_secure TINYINT(1) DEFAULT 1,
                virus_scan_status ENUM('pending', 'clean', 'infected', 'error') DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_ticket_id (ticket_id),
                INDEX idx_uploaded_by (uploaded_by),
                INDEX idx_created_at (created_at),
                FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE,
                FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE CASCADE
            )",
            
            // Add missing indexes for performance
            "CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(estado)",
            "CREATE INDEX IF NOT EXISTS idx_tickets_agente ON tickets(agente_id)", 
            "CREATE INDEX IF NOT EXISTS idx_tickets_cliente ON tickets(cliente_email)",
            "CREATE INDEX IF NOT EXISTS idx_tickets_created ON tickets(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
            "CREATE INDEX IF NOT EXISTS idx_users_rol ON users(rol)",
            
            // Insert default system configuration
            "INSERT IGNORE INTO system_config (config_key, config_value, is_sensitive) VALUES
                ('system_version', '2.0.0', 0),
                ('security_enabled', '1', 0),
                ('audit_enabled', '1', 0),
                ('maintenance_mode', '0', 0),
                ('max_login_attempts', '5', 0),
                ('session_timeout', '7200', 0),
                ('password_min_length', '8', 0),
                ('require_mfa', '0', 0)",
        ];
        
        // Execute migrations
        $database = app('database');
        
        foreach ($sql as $query) {
            try {
                $database->query($query);
                echo "✅ Migration executed: " . substr($query, 0, 50) . "...\n";
            } catch (Exception $e) {
                echo "❌ Migration failed: " . $e->getMessage() . "\n";
                echo "Query: " . substr($query, 0, 100) . "...\n";
            }
        }
    }
    
    /**
     * Rollback the migration
     */
    public function down(): void
    {
        $sql = [
            "DROP TABLE IF EXISTS file_uploads",
            "DROP TABLE IF EXISTS password_reset_tokens",
            "DROP TABLE IF EXISTS system_config",
            "DROP TABLE IF EXISTS rate_limits",
            "DROP TABLE IF EXISTS sessions",
            "DROP TABLE IF EXISTS audit_logs",
            "DROP TABLE IF EXISTS security_events",
            
            // Remove added columns from users table
            "ALTER TABLE users 
                DROP COLUMN IF EXISTS password_changed_at,
                DROP COLUMN IF EXISTS failed_login_attempts,
                DROP COLUMN IF EXISTS locked_until,
                DROP COLUMN IF EXISTS last_login_at,
                DROP COLUMN IF EXISTS last_login_ip,
                DROP COLUMN IF EXISTS mfa_secret,
                DROP COLUMN IF EXISTS mfa_enabled,
                DROP COLUMN IF EXISTS created_at,
                DROP COLUMN IF EXISTS updated_at",
                
            // Remove added columns from tickets table
            "ALTER TABLE tickets
                DROP COLUMN IF EXISTS priority,
                DROP COLUMN IF EXISTS estimated_resolution,
                DROP COLUMN IF EXISTS resolution_notes,
                DROP COLUMN IF EXISTS created_at,
                DROP COLUMN IF EXISTS updated_at"
        ];
        
        $database = app('database');
        
        foreach ($sql as $query) {
            try {
                $database->query($query);
                echo "✅ Rollback executed: " . substr($query, 0, 50) . "...\n";
            } catch (Exception $e) {
                echo "❌ Rollback failed: " . $e->getMessage() . "\n";
            }
        }
    }
}

// Migration runner
if (php_sapi_name() === 'cli') {
    echo "=== Sansouci-Desk Database Migration ===\n\n";
    
    try {
        require_once __DIR__ . '/../bootstrap/app.php';
        
        $migration = new CreateEnhancedSecurityTables();
        
        $action = $argv[1] ?? 'up';
        
        if ($action === 'up') {
            echo "Running migration...\n";
            $migration->up();
            echo "\n✅ Migration completed successfully!\n";
        } elseif ($action === 'down') {
            echo "Rolling back migration...\n";
            $migration->down();
            echo "\n✅ Rollback completed successfully!\n";
        } else {
            echo "Usage: php migrate.php [up|down]\n";
            exit(1);
        }
        
    } catch (Exception $e) {
        echo "\n❌ Migration failed: " . $e->getMessage() . "\n";
        exit(1);
    }
}
