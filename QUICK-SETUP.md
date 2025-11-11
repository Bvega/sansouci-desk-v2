# 🚀 QUICK SETUP GUIDE
## Sansouci-Desk V2.0 - 5-Minute Setup

**Get your modernized system running in 5 minutes!**

---

## 📦 **WHAT'S IN THE BOX**

This package contains:
- ✅ **Complete V2 Application** - Modernized, secure codebase
- ✅ **Security Framework** - Enterprise-grade protection
- ✅ **Database Migrations** - Enhanced table structure
- ✅ **Test Suite** - Security and functionality tests
- ✅ **Deployment Tools** - Automated setup scripts
- ✅ **Documentation** - Complete setup and security guides

---

## ⚡ **INSTANT SETUP (5 MINUTES)**

### **Step 1: Extract & Navigate**
```bash
unzip sansouci-desk-v2-complete.zip
cd sansouci-desk-v2/
```

### **Step 2: Run Automated Setup**
```bash
chmod +x deploy.sh
./deploy.sh
```
*The script will guide you through the entire setup process!*

### **Step 3: Configure Database**
Edit `.env` file:
```env
DB_DATABASE=sansouci_desk
DB_USERNAME=your_username
DB_PASSWORD=your_password
```

### **Step 4: Point Web Server**
Point your web server's document root to the `public/` directory.

**That's it! Your V2 system is ready! 🎉**

---

## 📂 **MANUAL SETUP (Alternative)**

If you prefer manual setup:

### **Prerequisites**
- PHP 8.1+
- MySQL 5.7+
- Composer
- Apache/Nginx

### **Install Dependencies**
```bash
composer install --optimize-autoloader --no-dev
```

### **Environment Setup**
```bash
cp .env.example .env
# Edit .env with your settings
```

### **Database Migration**
```bash
php database/migrations/001_create_enhanced_security_tables.php up
```

### **Set Permissions**
```bash
chmod -R 775 storage/ bootstrap/
```

---

## 🔧 **IMPORTANT CONFIGURATIONS**

### **Web Server Setup**

**Apache:**
- Document root: `/path/to/sansouci-desk-v2/public`
- Ensure mod_rewrite is enabled
- .htaccess file is included

**Nginx:**
```nginx
server {
    listen 80;
    server_name yourdomain.com;
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
}
```

### **Environment Variables (Required)**
```env
# Application
APP_KEY=base64:your_secure_key_here
APP_ENV=production
APP_DEBUG=false

# Database
DB_HOST=localhost
DB_DATABASE=sansouci_desk
DB_USERNAME=your_username
DB_PASSWORD=your_secure_password

# Email (SMTP)
MAIL_HOST=smtp.gmail.com
MAIL_USERNAME=your_email@domain.com
MAIL_PASSWORD=your_app_password
```

---

## 🔒 **SECURITY CHECKLIST**

Before going live:
- [ ] Set `APP_ENV=production` and `APP_DEBUG=false`
- [ ] Configure HTTPS/SSL
- [ ] Review the `SECURITY-CHECKLIST.md` file
- [ ] Run security tests: `vendor/bin/phpunit --testsuite=Security`
- [ ] Verify all URLs in `/src/`, `/config/`, `/vendor/` return 403/404

---

## 📊 **TESTING YOUR SETUP**

### **Basic Functionality Test**
1. Visit your domain - should show the customer portal
2. Try creating a test ticket
3. Access `/login` - should show admin login
4. Check email notifications work

### **Security Validation**
```bash
# Run security tests
vendor/bin/phpunit --testsuite=Security

# Check for vulnerabilities
composer audit

# Test blocked access
curl -I https://yourdomain.com/.env    # Should return 403
curl -I https://yourdomain.com/vendor/ # Should return 403
```

---

## 🆘 **TROUBLESHOOTING**

### **Common Issues**

**"Composer not found":**
```bash
curl -sS https://getcomposer.org/installer | php
sudo mv composer.phar /usr/local/bin/composer
```

**Permission errors:**
```bash
sudo chown -R www-data:www-data storage/ bootstrap/
sudo chmod -R 775 storage/ bootstrap/
```

**Database connection failed:**
- Check database credentials in `.env`
- Ensure database exists
- Verify database user permissions

**Page not found (404):**
- Check web server points to `public/` directory
- Ensure mod_rewrite is enabled (Apache)
- Check .htaccess file exists in `public/`

**Email not working:**
- Verify SMTP settings in `.env`
- Check firewall doesn't block SMTP ports
- Use app-specific passwords for Gmail

---

## 📞 **SUPPORT**

### **Documentation**
- `README.md` - Complete documentation
- `SECURITY-CHECKLIST.md` - Security deployment guide
- `tests/` directory - Example test cases

### **Log Files**
Monitor these for issues:
- `storage/logs/application.log`
- `storage/logs/security.log`
- Web server error logs

### **Verification Commands**
```bash
# Check file permissions
ls -la storage/ bootstrap/

# Test database connection
php -r "try { new PDO('mysql:host=localhost;dbname=sansouci_desk', 'user', 'pass'); echo 'OK'; } catch(Exception \$e) { echo \$e->getMessage(); }"

# Verify web server configuration
curl -I https://yourdomain.com
```

---

## 🎯 **NEXT STEPS**

1. **Production Deployment:**
   - Set `APP_ENV=production`
   - Enable HTTPS/SSL
   - Configure backups
   - Set up monitoring

2. **User Training:**
   - Interface is similar to V1
   - Enhanced security is transparent
   - New admin features available

3. **Customization:**
   - Update company branding
   - Configure email templates
   - Customize user roles

---

**🏁 Your enterprise-grade ticketing system is ready!**

*For detailed configuration and security options, see the complete README.md file.*
