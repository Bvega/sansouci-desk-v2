<?php

declare(strict_types=1);

namespace App\Database;

use PDO;
use PDOException;
use Exception;

/**
 * Secure Database Connection
 * Enhanced PDO wrapper with security controls and query optimization
 */
class Connection
{
    private PDO $pdo;
    
    /**
     * @var array<string, mixed>
     */
    private array $config;
    
    /**
     * @var array<int, array<string, mixed>>
     */
    private array $queryLog = [];
    
    private bool $logging = false;
    
    /**
     * @param array<string, mixed> $config
     */
    public function __construct(array $config)
    {
        $this->config = $config;
        $this->logging = env('QUERY_LOG_ENABLED', false);
        $this->connect();
    }
    
    /**
     * Establish secure database connection
     */
    private function connect(): void
    {
        try {
            $dsn = sprintf(
                'mysql:host=%s;port=%d;dbname=%s;charset=%s',
                $this->config['host'],
                $this->config['port'] ?? 3306,
                $this->config['database'],
                $this->config['charset'] ?? 'utf8mb4'
            );
            
            $options = array_merge([
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::ATTR_STRINGIFY_FETCHES => false,
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci",
                PDO::MYSQL_ATTR_USE_BUFFERED_QUERY => false,
                // Security: Disable multiple statements to prevent SQL injection
                PDO::MYSQL_ATTR_MULTI_STATEMENTS => false
            ], $this->config['options'] ?? []);
            
            $this->pdo = new PDO(
                $dsn,
                $this->config['username'],
                $this->config['password'],
                $options
            );
            
            // Additional security settings
            $this->pdo->exec("SET sql_mode = 'STRICT_TRANS_TABLES,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION'");
            
        } catch (PDOException $e) {
            // Log the error but don't expose database details
            error_log("Database connection failed: " . $e->getMessage());
            throw new Exception("Database connection failed. Please check your configuration.");
        }
    }
    
    /**
     * Execute prepared statement with parameters
     * @param array<string|int, mixed> $params
     */
    public function query(string $sql, array $params = []): DatabaseResult
    {
        $startTime = microtime(true);
        
        try {
            // Validate SQL to prevent dangerous operations
            $this->validateQuery($sql);
            
            $stmt = $this->pdo->prepare($sql);
            
            // Bind parameters with type checking
            $this->bindParameters($stmt, $params);
            
            $stmt->execute();
            
            // Log query if enabled
            if ($this->logging) {
                $this->logQuery($sql, $params, microtime(true) - $startTime);
            }
            
            return new DatabaseResult($stmt);
            
        } catch (PDOException $e) {
            // Log the error with context
            $this->logError($sql, $params, $e);
            throw new Exception("Query execution failed: " . $e->getMessage());
        }
    }
    
    /**
     * Execute SELECT query and return all results
     * @param array<string|int, mixed> $params
     * @return array<int, array<string, mixed>>
     */
    public function select(string $sql, array $params = []): array
    {
        $result = $this->query($sql, $params);
        return $result->fetchAll();
    }
    
    /**
     * Execute SELECT query and return first result
     * @param array<string|int, mixed> $params
     * @return array<string, mixed>|null
     */
    public function selectOne(string $sql, array $params = []): ?array
    {
        $result = $this->query($sql, $params);
        $row = $result->fetch();
        return $row ?: null;
    }
    
    /**
     * Execute INSERT statement and return last insert ID
     * @param array<string, mixed> $data
     */
    public function insert(string $table, array $data): int
    {
        $columns = implode(', ', array_keys($data));
        $placeholders = implode(', ', array_fill(0, count($data), '?'));
        
        $sql = "INSERT INTO {$table} ({$columns}) VALUES ({$placeholders})";
        
        $this->query($sql, array_values($data));
        
        return (int) $this->pdo->lastInsertId();
    }
    
    /**
     * Execute UPDATE statement and return affected rows
     * @param array<string, mixed> $data
     * @param array<string, mixed> $where
     */
    public function update(string $table, array $data, array $where): int
    {
        $set = implode(', ', array_map(fn($col) => "{$col} = ?", array_keys($data)));
        $whereClause = implode(' AND ', array_map(fn($col) => "{$col} = ?", array_keys($where)));
        
        $sql = "UPDATE {$table} SET {$set} WHERE {$whereClause}";
        $params = array_merge(array_values($data), array_values($where));
        
        $result = $this->query($sql, $params);
        return $result->rowCount();
    }
    
    /**
     * Execute DELETE statement and return affected rows
     * @param array<string, mixed> $where
     */
    public function delete(string $table, array $where): int
    {
        $whereClause = implode(' AND ', array_map(fn($col) => "{$col} = ?", array_keys($where)));
        
        $sql = "DELETE FROM {$table} WHERE {$whereClause}";
        
        $result = $this->query($sql, array_values($where));
        return $result->rowCount();
    }
    
    /**
     * Start database transaction
     */
    public function beginTransaction(): void
    {
        $this->pdo->beginTransaction();
    }
    
    /**
     * Commit database transaction
     */
    public function commit(): void
    {
        $this->pdo->commit();
    }
    
    /**
     * Rollback database transaction
     */
    public function rollback(): void
    {
        $this->pdo->rollBack();
    }
    
    /**
     * Execute callback within transaction
     */
    public function transaction(callable $callback): mixed
    {
        $this->beginTransaction();
        
        try {
            $result = $callback($this);
            $this->commit();
            return $result;
        } catch (Exception $e) {
            $this->rollback();
            throw $e;
        }
    }
    
    /**
     * Validate SQL query for security
     */
    private function validateQuery(string $sql): void
    {
        $sql = strtolower(trim($sql));
        
        // Dangerous patterns that should never be allowed
        $dangerousPatterns = [
            '/;\s*(drop|truncate|delete|alter|create)\s+/i',
            '/union\s+select/i',
            '/into\s+outfile/i',
            '/load_file\s*\(/i',
            '/benchmark\s*\(/i',
            '/sleep\s*\(/i',
            '/pg_sleep\s*\(/i'
        ];
        
        foreach ($dangerousPatterns as $pattern) {
            if (preg_match($pattern, $sql)) {
                log_security_event('dangerous_sql_pattern', ['pattern' => $pattern, 'sql' => substr($sql, 0, 100)]);
                throw new Exception("Dangerous SQL pattern detected");
            }
        }
        
        // Additional checks for production environment
        if (env('APP_ENV') === 'production') {
            // Prevent multiple statements
            if (substr_count($sql, ';') > 1) {
                throw new Exception("Multiple statements not allowed");
            }
        }
    }
    
    /**
     * Bind parameters to prepared statement with type detection
     * @param array<string|int, mixed> $params
     */
    private function bindParameters(\PDOStatement $stmt, array $params): void
    {
        foreach ($params as $index => $value) {
            $param = is_int($index) ? $index + 1 : $index;
            
            $type = match (gettype($value)) {
                'boolean' => PDO::PARAM_BOOL,
                'integer' => PDO::PARAM_INT,
                'NULL' => PDO::PARAM_NULL,
                default => PDO::PARAM_STR
            };
            
            $stmt->bindValue($param, $value, $type);
        }
    }
    
    /**
     * Log SQL query for debugging
     * @param array<string|int, mixed> $params
     */
    private function logQuery(string $sql, array $params, float $executionTime): void
    {
        $this->queryLog[] = [
            'sql' => $sql,
            'params' => $params,
            'time' => $executionTime,
            'timestamp' => date('Y-m-d H:i:s')
        ];
        
        // Limit log size
        if (count($this->queryLog) > 1000) {
            $this->queryLog = array_slice($this->queryLog, -500);
        }
    }
    
    /**
     * Log database errors
     * @param array<string|int, mixed> $params
     */
    private function logError(string $sql, array $params, PDOException $e): void
    {
        $logger = app('logger');
        
        $logger->error('Database query failed', [
            'sql' => $sql,
            'params' => $params,
            'error' => $e->getMessage(),
            'file' => $e->getFile(),
            'line' => $e->getLine()
        ]);
    }
    
    /**
     * Get query log
     * @return array<int, array<string, mixed>>
     */
    public function getQueryLog(): array
    {
        return $this->queryLog;
    }
    
    /**
     * Clear query log
     */
    public function clearQueryLog(): void
    {
        $this->queryLog = [];
    }
    
    /**
     * Get PDO instance (use with caution)
     */
    public function getPdo(): PDO
    {
        return $this->pdo;
    }
    
    /**
     * Get last insert ID - FIXED: Proper return type handling
     */
    public function lastInsertId(): string
    {
        $result = $this->pdo->lastInsertId();
        return $result !== false ? $result : '0';
    }
    
    /**
     * Check if table exists
     */
    public function tableExists(string $table): bool
    {
        $result = $this->selectOne(
            "SELECT COUNT(*) as count FROM information_schema.tables WHERE table_schema = ? AND table_name = ?",
            [$this->config['database'], $table]
        );
        
        return ($result['count'] ?? 0) > 0;
    }
    
    /**
     * Get table columns
     * @return array<int, array<string, mixed>>
     */
    public function getTableColumns(string $table): array
    {
        $result = $this->select(
            "SELECT column_name, data_type, is_nullable, column_default 
             FROM information_schema.columns 
             WHERE table_schema = ? AND table_name = ?
             ORDER BY ordinal_position",
            [$this->config['database'], $table]
        );
        
        return $result;
    }
}

/**
 * Database Result Wrapper
 */
class DatabaseResult
{
    private \PDOStatement $statement;
    
    public function __construct(\PDOStatement $statement)
    {
        $this->statement = $statement;
    }
    
    /**
     * Fetch single row
     * @return array<string, mixed>|false
     */
    public function fetch(): array|false
    {
        return $this->statement->fetch(PDO::FETCH_ASSOC);
    }
    
    /**
     * Fetch all rows
     * @return array<int, array<string, mixed>>
     */
    public function fetchAll(): array
    {
        return $this->statement->fetchAll(PDO::FETCH_ASSOC);
    }
    
    /**
     * Fetch single column value
     */
    public function fetchColumn(int $column = 0): mixed
    {
        return $this->statement->fetchColumn($column);
    }
    
    /**
     * Get number of affected rows
     */
    public function rowCount(): int
    {
        return $this->statement->rowCount();
    }
    
    /**
     * Get column count
     */
    public function columnCount(): int
    {
        return $this->statement->columnCount();
    }
}