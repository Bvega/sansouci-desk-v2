# Sansouci-Desk V2.0 - Enterprise Ticketing System

## 🚀 **MODERNIZED & SECURITY-HARDENED VERSION**

This is the completely modernized version of the Sansouci-Desk ticketing system, implementing enterprise-grade security, performance optimizations, and best practices.

---

## 📋 **WHAT'S NEW IN V2.0**

### 🔒 **Security Enhancements**
- ✅ **SQL Injection Protection**: All queries use prepared statements
- ✅ **CSRF Protection**: Token-based request validation
- ✅ **XSS Prevention**: Input sanitization and output escaping
- ✅ **Secure Sessions**: Hardened session management with IP validation
- ✅ **Rate Limiting**: Prevents brute force attacks
- ✅ **Security Headers**: Complete CSP, HSTS, and security header implementation
- ✅ **Audit Logging**: Comprehensive security event tracking
- ✅ **Input Validation**: Centralized validation with security checks

### ⚡ **Performance Improvements**
- ✅ **Database Optimization**: Proper indexing and query optimization
- ✅ **Caching Layer**: Application-level caching for better performance
- ✅ **Autoloading**: PSR-4 compliant autoloading
- ✅ **Dependency Injection**: Clean dependency management
- ✅ **Query Monitoring**: Performance tracking and optimization

### 🏗️ **Architecture Modernization**
- ✅ **MVC Pattern**: Clean separation of concerns
- ✅ **Routing System**: Clean URLs with parameter support
- ✅ **Middleware Stack**: Request/response pipeline
- ✅ **Error Handling**: Secure error handling and logging
- ✅ **Configuration Management**: Environment-based configuration
- ✅ **Testing Framework**: Comprehensive test suite

---

## 📁 **PROJECT STRUCTURE**

```
sansouci-desk-v2/
├── 📁 src/                     # Application source code
│   ├── 📁 Controllers/         # Request handlers
│   ├── 📁 Models/             # Data models
│   ├── 📁 Services/           # Business logic
│   ├── 📁 Middleware/         # Request middleware
│   ├── 📁 Security/           # Security components
│   ├── 📁 Database/           # Database layer
│   └── 📄 helpers.php         # Global helper functions
├── 📁 config/                 # Configuration files
├── 📁 database/               # Database migrations
│   └── 📁 migrations/         # Database schema updates
├── 📁 tests/                  # Test suite
│   ├── 📁 Unit/              # Unit tests
│   ├── 📁 Integration/       # Integration tests
│   └── 📁 Security/          # Security tests
├── 📁 public/                 # Web accessible files
│   ├── 📄 index.php          # Application entry point
│   └── 📄 .htaccess          # Apache security configuration
├── 📁 resources/
│   └── 📁 views/             # Template files
├── 📁 storage/               # Application storage
│   ├── 📁 logs/              # Log files
│   ├── 📁 cache/             # Cache storage
│   └── 📁 uploads/           # File uploads
├── 📁 bootstrap/             # Application bootstrap
├── 📄 composer.json          # Dependencies
├── 📄 .env.example          # Environment template
└── 📄 README.md             # This file
```

---

## 🛠️ **INSTALLATION GUIDE**

### **Prerequisites**
- PHP 8.1 or higher
- MySQL 5.7 or higher
- Apache/Nginx with mod_rewrite
- Composer (PHP dependency manager)

### **Step 1: Download & Extract**
```bash
# Extract the zip file to your web server directory
unzip sansouci-desk-v2.zip
cd sansouci-desk-v2/
```

### **Step 2: Install Dependencies**
```bash
# Install Composer if not already installed
curl -sS https://getcomposer.org/installer | php
sudo mv composer.phar /usr/local/bin/composer

# Install application dependencies
composer install --optimize-autoloader --no-dev
```

### **Step 3: Environment Configuration**
```bash
# Copy environment file
cp .env.example .env

# Generate secure application key
php -r "echo 'APP_KEY=base64:' . base64_encode(random_bytes(32)) . PHP_EOL;"

# Edit .env file with your settings
nano .env
```

**Required .env Configuration:**
```env
# Database Settings
DB_HOST=localhost
DB_DATABASE=sansouci_desk
DB_USERNAME=your_username
DB_PASSWORD=your_password

# Application Key (generate secure key)
APP_KEY=base64:your_secure_key_here

# Email Settings
MAIL_HOST=your_smtp_host
MAIL_USERNAME=your_email
MAIL_PASSWORD=your_password
```

### **Step 4: Database Setup**
```bash
# Create database
mysql -u root -p -e "CREATE DATABASE sansouci_desk CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"

# Import original structure (from your V1 backup)
mysql -u root -p sansouci_desk < your_original_database.sql

# Run V2 security enhancements migration
php database/migrations/001_create_enhanced_security_tables.php up
```

### **Step 5: File Permissions**
```bash
# Set proper permissions
sudo chown -R www-data:www-data storage/ bootstrap/
sudo chmod -R 775 storage/ bootstrap/
sudo chmod 644 .env
```

### **Step 6: Web Server Configuration**

**Apache (.htaccess included):**
- Point document root to `public/` directory
- Ensure mod_rewrite is enabled
- .htaccess file is already configured

**Nginx Configuration:**
```nginx
server {
    listen 80;
    server_name your-domain.com;
    root /path/to/sansouci-desk-v2/public;
    index index.php;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
        include fastcgi_params;
    }

    # Security headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
}
```

---

## 🔧 **CONFIGURATION OPTIONS**

### **Security Settings**
```env
# CSRF Protection
CSRF_TOKEN_LIFETIME=3600
CSRF_REGENERATE_ON_LOGIN=true

# Rate Limiting
RATE_LIMIT_LOGIN_ATTEMPTS=5
RATE_LIMIT_WINDOW=900
RATE_LIMIT_ENABLED=true

# Password Requirements
PASSWORD_MIN_LENGTH=8
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_NUMBERS=true
PASSWORD_REQUIRE_SYMBOLS=false

# Security Headers
SECURITY_HEADERS_ENABLED=true
CONTENT_SECURITY_POLICY_ENABLED=true
```

### **Performance Settings**
```env
# Caching
CACHE_DRIVER=file
CACHE_PREFIX=sansouci_desk

# Logging
LOG_CHANNEL=daily
LOG_LEVEL=warning
LOG_DAYS=14

# Query Optimization
QUERY_LOG_ENABLED=false
```

---

## 🧪 **TESTING**

### **Run Security Tests**
```bash
# Install development dependencies
composer install

# Run all tests
vendor/bin/phpunit

# Run only security tests
vendor/bin/phpunit --testsuite=Security

# Generate coverage report
vendor/bin/phpunit --coverage-html coverage/
```

### **Security Validation**
```bash
# Static security analysis
vendor/bin/psalm --security-analysis

# Code quality check
vendor/bin/phpstan analyse --level=8

# Dependency security audit
composer audit
```

---

## 📊 **MIGRATION FROM V1**

### **Data Migration Strategy**

1. **Backup Original System**
   ```bash
   mysqldump -u root -p sansouci_desk > backup_v1_$(date +%Y%m%d).sql
   cp -r /path/to/original/sansouci-desk /backup/sansouci-desk-v1-backup/
   ```

2. **Parallel Deployment**
   - Deploy V2 on subdomain (e.g., v2.yourdomain.com)
   - Test thoroughly with real data
   - Gradually migrate users

3. **URL Preservation**
   - V2 maintains same functionality
   - URLs can be redirected via .htaccess
   - API endpoints remain compatible

### **User Training**
- Interface remains familiar
- Enhanced security is transparent to users
- Admin features have improved UX

---

## 🔒 **SECURITY FEATURES**

### **Authentication & Authorization**
- Secure password hashing (bcrypt)
- Session hijacking prevention
- Role-based access control
- Multi-factor authentication ready

### **Input Security**
- All inputs validated and sanitized
- SQL injection prevention
- XSS attack prevention
- CSRF token protection

### **Infrastructure Security**
- Security headers implementation
- Rate limiting and DDoS protection
- Audit logging and monitoring
- Secure file upload handling

---

## 📈 **MONITORING & MAINTENANCE**

### **Log Files**
```
storage/logs/
├── application.log     # General application logs
├── security.log       # Security events
├── audit.log          # Audit trail
└── error.log          # Error tracking
```

### **Performance Monitoring**
- Database query monitoring
- Response time tracking
- Memory usage optimization
- Cache hit ratio analysis

### **Security Monitoring**
- Failed login attempt tracking
- Suspicious activity alerts
- IP-based threat detection
- Automated security reporting

---

## 🚀 **DEPLOYMENT CHECKLIST**

### **Pre-Production**
- [ ] Install dependencies (`composer install --no-dev`)
- [ ] Configure environment variables
- [ ] Set up database and run migrations
- [ ] Configure web server
- [ ] Set file permissions
- [ ] Test security features

### **Production**
- [ ] Set `APP_ENV=production`
- [ ] Set `APP_DEBUG=false`
- [ ] Enable HTTPS and HSTS
- [ ] Configure backup strategy
- [ ] Set up monitoring
- [ ] Configure log rotation

### **Post-Deployment**
- [ ] Verify all features work
- [ ] Test user authentication
- [ ] Validate email functionality
- [ ] Check security headers
- [ ] Monitor performance
- [ ] Train end users

---

## 📞 **SUPPORT & TROUBLESHOOTING**

### **Common Issues**

**Composer Installation Failed:**
```bash
# Try with memory limit increase
php -d memory_limit=512M /usr/local/bin/composer install
```

**Permission Errors:**
```bash
# Fix ownership and permissions
sudo chown -R www-data:www-data .
sudo chmod -R 755 .
sudo chmod -R 775 storage bootstrap
```

**Database Connection Errors:**
- Verify database credentials in `.env`
- Check database server is running
- Ensure database exists and has proper charset

**Email Not Sending:**
- Verify SMTP credentials
- Check firewall/network restrictions
- Test with different SMTP provider

### **Performance Optimization**
- Enable OPcache in production
- Configure database query caching
- Implement Redis for session storage
- Use CDN for static assets

---

## 📋 **VERSION INFORMATION**

**Current Version:** 2.0.0  
**Release Date:** November 2025  
**PHP Version:** 8.1+  
**Database:** MySQL 5.7+  
**License:** Proprietary (Sansouci Puerto de Santo Domingo)  

**Previous Version Compatibility:** Full backward compatibility with V1.1 database structure

---

## 🎯 **WHAT'S NEXT**

### **Phase 2 Enhancements (Next Sprint)**
- Real-time notifications
- Advanced reporting dashboard
- Mobile app API
- Advanced user management
- File attachment security scanning

### **Future Roadmap**
- Multi-language support
- Advanced workflow automation
- Integration APIs
- Advanced analytics
- Machine learning for ticket classification

---

**For technical support and questions, contact the development team.**

**This system is production-ready and implements enterprise-grade security standards.**
