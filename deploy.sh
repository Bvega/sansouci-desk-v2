#!/bin/bash

# Sansouci-Desk V2 Deployment Script
# Automates the deployment process with security checks

set -e  # Exit on any error

echo "🚀 Sansouci-Desk V2 Deployment Script"
echo "====================================="
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Check if running as root (not recommended)
if [ "$EUID" -eq 0 ]; then
    print_warning "Running as root is not recommended for security reasons"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_error "Deployment cancelled"
    fi
fi

# Step 1: Check Prerequisites
print_status "Checking prerequisites..."

# Check PHP version
if ! command -v php &> /dev/null; then
    print_error "PHP is not installed"
fi

PHP_VERSION=$(php -v | head -n1 | cut -d' ' -f2 | cut -d. -f1-2)
if [ "$(printf '%s\n' "8.1" "$PHP_VERSION" | sort -V | head -n1)" != "8.1" ]; then
    print_error "PHP 8.1 or higher required. Current version: $PHP_VERSION"
fi

# Check MySQL
if ! command -v mysql &> /dev/null; then
    print_warning "MySQL client not found. Make sure MySQL server is available"
fi

# Check Composer
if ! command -v composer &> /dev/null; then
    print_status "Installing Composer..."
    curl -sS https://getcomposer.org/installer | php
    sudo mv composer.phar /usr/local/bin/composer
    print_success "Composer installed"
fi

print_success "Prerequisites check completed"

# Step 2: Install Dependencies
print_status "Installing dependencies..."
composer install --optimize-autoloader --no-dev
print_success "Dependencies installed"

# Step 3: Environment Configuration
if [ ! -f .env ]; then
    print_status "Setting up environment configuration..."
    cp .env.example .env
    
    # Generate secure APP_KEY
    APP_KEY=$(php -r "echo 'base64:' . base64_encode(random_bytes(32));")
    sed -i "s/APP_KEY=.*/APP_KEY=$APP_KEY/" .env
    
    print_success "Environment file created"
    print_warning "Please configure your database and email settings in .env file"
    
    read -p "Press Enter to open .env file for editing..."
    ${EDITOR:-nano} .env
else
    print_success "Environment file already exists"
fi

# Step 4: Database Setup
print_status "Checking database configuration..."

# Source environment variables
set -a
source .env
set +a

if [ -z "$DB_DATABASE" ]; then
    print_error "DB_DATABASE not set in .env file"
fi

# Test database connection
if mysql -h"$DB_HOST" -u"$DB_USERNAME" -p"$DB_PASSWORD" -e "USE $DB_DATABASE" 2>/dev/null; then
    print_success "Database connection successful"
    
    read -p "Run database migrations? (Y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        print_status "Running database migrations..."
        php database/migrations/001_create_enhanced_security_tables.php up
        print_success "Database migrations completed"
    fi
else
    print_warning "Cannot connect to database. Please verify your database configuration"
fi

# Step 5: File Permissions
print_status "Setting file permissions..."

# Create necessary directories
mkdir -p storage/logs storage/cache storage/uploads bootstrap/cache

# Set permissions
chmod -R 775 storage/ bootstrap/
chmod 644 .env

# If running under Apache, try to set ownership
if command -v apache2 &> /dev/null; then
    if [ -w /etc/apache2/ ]; then
        sudo chown -R www-data:www-data storage/ bootstrap/
        print_success "Ownership set for Apache"
    fi
fi

print_success "File permissions configured"

# Step 6: Security Validation
print_status "Running security validation..."

# Check if .env is accessible via web (security risk)
if [ -f public/.env ]; then
    print_error ".env file found in public directory - SECURITY RISK!"
fi

# Validate .htaccess file exists
if [ ! -f public/.htaccess ]; then
    print_warning "public/.htaccess not found. URL rewriting may not work"
fi

# Check for sensitive files in public directory
if find public/ -name "*.php" -not -path "public/index.php" | grep -q .; then
    print_warning "Non-entry PHP files found in public directory"
fi

print_success "Security validation completed"

# Step 7: Testing
if command -v vendor/bin/phpunit &> /dev/null; then
    read -p "Run security tests? (Y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        print_status "Running security tests..."
        vendor/bin/phpunit --testsuite=Security
        print_success "Security tests completed"
    fi
fi

# Step 8: Final Checks
print_status "Performing final checks..."

# Check web server configuration
if command -v apache2 &> /dev/null; then
    if ! apache2ctl -M | grep -q rewrite; then
        print_warning "Apache mod_rewrite not enabled. URL rewriting will not work"
    fi
fi

print_success "Final checks completed"

echo
echo "🎉 Deployment completed successfully!"
echo
print_status "Next steps:"
echo "1. Configure your web server to point to the 'public' directory"
echo "2. Set APP_ENV=production in .env for production deployment"
echo "3. Test the application thoroughly"
echo "4. Set up SSL certificate for HTTPS"
echo "5. Configure backup strategy"
echo
print_status "Application URL: ${APP_URL:-http://localhost}"
print_status "Default login: Configure users via database or admin panel"

# Performance recommendations
echo
print_status "Performance recommendations:"
echo "- Enable OPcache in production"
echo "- Configure Redis for session storage"
echo "- Set up database query caching"
echo "- Use a CDN for static assets"

echo
print_success "Deployment script finished! 🚀"
