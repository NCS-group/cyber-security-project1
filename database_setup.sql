-- =====================================================
-- XAMPP MySQL Database Setup
-- =====================================================
-- Instructions:
-- 1. Start XAMPP and run MySQL
-- 2. Open phpMyAdmin (http://localhost/phpmyadmin)
-- 3. Click on "SQL" tab
-- 4. Copy and paste this entire file
-- 5. Click "Go" to execute
-- =====================================================

-- Create database
CREATE DATABASE IF NOT EXISTS userdb;

-- Use the database
USE userdb;

-- Drop table if exists (for fresh start)
DROP TABLE IF EXISTS users;

-- Create users table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    is_vip BOOLEAN DEFAULT FALSE,
    vip_expiry DATE NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create scan history table
CREATE TABLE scan_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    scan_type VARCHAR(50) NOT NULL,
    target VARCHAR(255) NOT NULL,
    results TEXT,
    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create payment requests table
CREATE TABLE payment_requests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    username VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL,
    payment_method VARCHAR(50) NOT NULL,
    transaction_id VARCHAR(100),
    amount DECIMAL(10,2) NOT NULL,
    status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
    screenshot_path VARCHAR(255),
    request_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    approved_date TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Insert a test user (optional)
-- Username: testuser
-- Email: test@example.com
-- Password: test123
INSERT INTO users (username, email, password, is_vip) VALUES ('testuser', 'test@example.com', 'test123', FALSE);

-- Insert a VIP test user (ONLY ONE VIP USER)
-- Username: vipuser
-- Email: vip@example.com
-- Password: vip123
INSERT INTO users (username, email, password, is_vip, vip_expiry) VALUES ('vipuser', 'vip@example.com', 'vip123', TRUE, DATE_ADD(CURDATE(), INTERVAL 365 DAY));

-- Create admin user for approving payments
-- Username: admin
-- Email: admin@example.com
-- Password: admin123
INSERT INTO users (username, email, password, is_vip) VALUES ('admin', 'admin@example.com', 'admin123', TRUE);

-- Verify table creation
SELECT * FROM users;
SELECT * FROM scan_history;

-- =====================================================
-- Setup Complete!
-- =====================================================
