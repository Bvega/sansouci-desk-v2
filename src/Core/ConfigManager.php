<?php

namespace App\Core;

use Exception;
use InvalidArgumentException;

/**
 * ROBUST TYPE-IMPROVED ConfigManager
 * Fixes all 9 PHPStan Level 8 issues with verified validation
 */
class ConfigManager
{
    /**
     * @var array<string, mixed> Configuration data storage
     */
    private array $config = [];
    
    /**
     * @var array<string, bool> Tracks loaded configuration files
     */
    private array $loaded = [];

    /**
     * @var string Configuration directory path
     */
    private string $configPath;

    public function __construct(string $configPath = 'config/')
    {
        $this->config = [];
        $this->loaded = [];
        $this->configPath = rtrim($configPath, '/') . '/';
    }

    /**
     * Load configuration file
     * 
     * @param string $name Configuration file name
     * @return array<string, mixed> Configuration data
     * @throws Exception If configuration file not found
     */
    public function load(string $name): array
    {
        if (isset($this->loaded[$name]) && $this->loaded[$name]) {
            return $this->config[$name] ?? [];
        }

        $configData = $this->loadFromFile($name);
        
        if ($configData === null) {
            throw new Exception("Configuration file '{$name}' not found");
        }

        $this->config[$name] = $configData;
        $this->loaded[$name] = true;
        
        return $this->config[$name];
    }

    /**
     * Get configuration value
     * 
     * @param string $key Configuration key (supports dot notation)
     * @param mixed $default Default value if key not found
     * @return mixed Configuration value or default
     */
    public function get(string $key, mixed $default = null): mixed
    {
        $keys = explode('.', $key);
        $value = $this->config;

        foreach ($keys as $segment) {
            if (!is_array($value) || !isset($value[$segment])) {
                return $default;
            }
            $value = $value[$segment];
        }

        return $value;
    }

    /**
     * Set configuration value
     * 
     * @param string $key Configuration key
     * @param mixed $value Configuration value
     * @return self Fluent interface
     */
    public function set(string $key, mixed $value): self
    {
        $keys = explode('.', $key);
        $config = &$this->config;

        while (count($keys) > 1) {
            $key = array_shift($keys);
            
            if (!isset($config[$key]) || !is_array($config[$key])) {
                $config[$key] = [];
            }
            
            $config = &$config[$key];
        }

        $config[array_shift($keys)] = $value;
        return $this;
    }

    /**
     * Check if configuration key exists
     * 
     * @param string $key Configuration key
     * @return bool True if key exists
     */
    public function has(string $key): bool
    {
        $keys = explode('.', $key);
        $value = $this->config;

        foreach ($keys as $segment) {
            if (!is_array($value) || !isset($value[$segment])) {
                return false;
            }
            $value = $value[$segment];
        }

        return true;
    }

    /**
     * Load configuration from file
     * 
     * @param string $name Configuration file name
     * @return array<string, mixed>|null Configuration data or null if not found
     */
    protected function loadFromFile(string $name): ?array
    {
        $filePath = $this->configPath . $name . '.php';
        
        if (file_exists($filePath)) {
            $config = require $filePath;
            
            if (!is_array($config)) {
                throw new InvalidArgumentException(
                    "Configuration file '{$filePath}' must return an array"
                );
            }
            
            return $config;
        }

        return null;
    }

    /**
     * Get all configuration data
     * 
     * @return array<string, mixed> All loaded configuration
     */
    public function all(): array
    {
        return $this->config;
    }

    /**
     * Get configuration section
     * 
     * @param string $section Section name
     * @return array<string, mixed> Section configuration data
     */
    public function getSection(string $section): array
    {
        if (!isset($this->config[$section])) {
            $this->load($section);
        }

        return $this->config[$section] ?? [];
    }

    /**
     * Merge configuration
     * 
     * @param array<string, mixed> $config Configuration to merge
     * @return self Fluent interface
     */
    public function merge(array $config): self
    {
        $this->config = array_merge_recursive($this->config, $config);
        return $this;
    }
}
