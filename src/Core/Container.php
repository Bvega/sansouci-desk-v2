<?php

declare(strict_types=1);

namespace App\Core;

use Exception;
use ReflectionClass;
use ReflectionException;
use ReflectionType;
use ReflectionNamedType;

/**
 * Dependency Injection Container
 * Manages service registration and resolution with security considerations
 */
class Container
{
    /**
     * @var array<string, array<string, mixed>>
     */
    private array $bindings = [];
    
    /**
     * @var array<string, object>
     */
    private array $instances = [];
    
    /**
     * @var array<string, bool>
     */
    private array $singletons = [];
    
    /**
     * Register a binding in the container
     */
    public function bind(string $abstract, callable|string|null $concrete = null): void
    {
        if ($concrete === null) {
            $concrete = $abstract;
        }
        
        $this->bindings[$abstract] = [
            'concrete' => $concrete,
            'singleton' => false
        ];
    }
    
    /**
     * Register a singleton binding
     */
    public function singleton(string $abstract, callable|string|object $concrete): void
    {
        if (is_object($concrete)) {
            $this->instances[$abstract] = $concrete;
            return;
        }
        
        $this->bindings[$abstract] = [
            'concrete' => $concrete,
            'singleton' => true
        ];
    }
    
    /**
     * Resolve a service from the container
     */
    public function get(string $abstract): mixed
    {
        // Return existing singleton instance
        if (isset($this->instances[$abstract])) {
            return $this->instances[$abstract];
        }
        
        // Check if binding exists
        if (!isset($this->bindings[$abstract])) {
            // Try to auto-resolve if it's a class
            if (class_exists($abstract)) {
                return $this->resolve($abstract);
            }
            
            throw new Exception("Service not found: {$abstract}");
        }
        
        $binding = $this->bindings[$abstract];
        $concrete = $binding['concrete'];
        
        // Resolve the concrete implementation
        if (is_callable($concrete)) {
            $instance = $concrete($this);
        } else {
            $instance = $this->resolve($concrete);
        }
        
        // Store singleton instances
        if ($binding['singleton']) {
            $this->instances[$abstract] = $instance;
        }
        
        return $instance;
    }
    
    /**
     * Resolve a class with dependency injection
     */
    private function resolve(string $class): object
    {
        try {
            // FIXED: Ensure class exists before creating ReflectionClass
            if (!class_exists($class)) {
                throw new Exception("Class {$class} not found");
            }
            
            $reflection = new ReflectionClass($class);
            
            // Check if class is instantiable
            if (!$reflection->isInstantiable()) {
                throw new Exception("Class {$class} is not instantiable");
            }
            
            $constructor = $reflection->getConstructor();
            
            // No constructor, just instantiate
            if (!$constructor) {
                return new $class();
            }
            
            // Resolve constructor dependencies
            $parameters = $constructor->getParameters();
            $dependencies = [];
            
            foreach ($parameters as $parameter) {
                $type = $parameter->getType();
                
                // FIXED: Proper ReflectionType handling
                if (!$type) {
                    // No type hint
                    if ($parameter->isDefaultValueAvailable()) {
                        $dependencies[] = $parameter->getDefaultValue();
                    } else {
                        throw new Exception(
                            "Cannot resolve parameter {$parameter->getName()} in {$class}"
                        );
                    }
                } else {
                    // Check if it's a ReflectionNamedType (PHP 8+ compatibility)
                    if ($type instanceof ReflectionNamedType) {
                        if ($type->isBuiltin()) {
                            // Handle built-in types
                            if ($parameter->isDefaultValueAvailable()) {
                                $dependencies[] = $parameter->getDefaultValue();
                            } else {
                                throw new Exception(
                                    "Cannot resolve built-in parameter {$parameter->getName()} in {$class}"
                                );
                            }
                        } else {
                            // Resolve class dependency
                            $dependencies[] = $this->get($type->getName());
                        }
                    } else {
                        // Fallback for older PHP versions or union types
                        if ($parameter->isDefaultValueAvailable()) {
                            $dependencies[] = $parameter->getDefaultValue();
                        } else {
                            throw new Exception(
                                "Cannot resolve complex parameter {$parameter->getName()} in {$class}"
                            );
                        }
                    }
                }
            }
            
            return $reflection->newInstanceArgs($dependencies);
            
        } catch (ReflectionException $e) {
            throw new Exception("Cannot resolve class {$class}: " . $e->getMessage());
        }
    }
    
    /**
     * Check if a service is bound
     */
    public function has(string $abstract): bool
    {
        return isset($this->bindings[$abstract]) || isset($this->instances[$abstract]);
    }
    
    /**
     * Remove a binding from the container
     */
    public function forget(string $abstract): void
    {
        unset($this->bindings[$abstract], $this->instances[$abstract]);
    }
    
    /**
     * Get all registered services (for debugging)
     * @return array<int, string>
     */
    public function getRegisteredServices(): array
    {
        return array_merge(
            array_keys($this->bindings),
            array_keys($this->instances)
        );
    }
    
    /**
     * Register core application services
     */
    public function registerCoreServices(): void
    {
        // Register database connection
        $this->singleton('database', function() {
            if (class_exists('\App\Database\Connection')) {
                return new \App\Database\Connection([
                    'host' => env('DB_HOST'),
                    'database' => env('DB_DATABASE'),
                    'username' => env('DB_USERNAME'),
                    'password' => env('DB_PASSWORD'),
                    'charset' => 'utf8mb4',
                    'options' => [
                        \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
                        \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
                        \PDO::ATTR_EMULATE_PREPARES => false,
                    ]
                ]);
            }
            throw new Exception('Database connection class not available');
        });
        
        // Register email service - FIXED: Conditional class loading
        $this->singleton('email', function() {
            if (class_exists('\App\Services\EmailService')) {
                return new \App\Services\EmailService([
                    'host' => env('MAIL_HOST'),
                    'port' => env('MAIL_PORT'),
                    'username' => env('MAIL_USERNAME'),
                    'password' => env('MAIL_PASSWORD'),
                    'encryption' => env('MAIL_ENCRYPTION'),
                    'from_address' => env('MAIL_FROM_ADDRESS'),
                    'from_name' => env('MAIL_FROM_NAME')
                ]);
            }
            throw new Exception('Email service not available');
        });
        
        // Register authentication service - FIXED: Conditional class loading
        $this->singleton('auth', function($container) {
            if (class_exists('\App\Services\AuthService')) {
                return new \App\Services\AuthService(
                    $container->get('database'),
                    $container->get('security')
                );
            }
            throw new Exception('Auth service not available');
        });
        
        // Register validation service
        $this->singleton('validator', function() {
            if (class_exists('\App\Services\ValidationService')) {
                return new \App\Services\ValidationService();
            }
            throw new Exception('Validation service not available');
        });
    }

    /**
     * Get container statistics for debugging
     * 
     * @return array<string, int> Container statistics
     */
    public function getStats(): array
    {
        return [
            "bindings" => count($this->bindings),
            "instances" => count($this->instances),
            "singletons" => count($this->singletons),
            "aliases" => 0, // Fixed: Remove undefined property references
            "tags" => 0     // Fixed: Remove undefined property references
        ];
    }
}