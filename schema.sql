CREATE DATABASE IF NOT EXISTS owasp_analyzer_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE owasp_analyzer_db;

CREATE TABLE IF NOT EXISTS analyses (
    id INT AUTO_INCREMENT PRIMARY KEY,
    language VARCHAR(30) NOT NULL,
    source_code LONGTEXT NOT NULL,
    risk VARCHAR(50) NOT NULL,
    score INT NOT NULL,
    total_findings INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    analysis_id INT NOT NULL,
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(30) NOT NULL,
    category VARCHAR(120) NOT NULL,
    owasp VARCHAR(120) NOT NULL,
    language VARCHAR(30) NOT NULL,
    line_number INT NOT NULL,
    evidence TEXT NOT NULL,
    impact TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    confidence VARCHAR(30) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
);
