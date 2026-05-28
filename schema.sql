CREATE DATABASE IF NOT EXISTS owasp_analyzer_db
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

USE owasp_analyzer_db;

CREATE TABLE IF NOT EXISTS analyses (
    id INT AUTO_INCREMENT PRIMARY KEY,
    language VARCHAR(30) NOT NULL,
    source_code LONGTEXT NOT NULL,
    source_hash CHAR(64) NULL,
    risk VARCHAR(50) NOT NULL,
    score INT NOT NULL,
    total_findings INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_analyses_created_at (created_at),
    INDEX idx_analyses_language (language),
    INDEX idx_analyses_risk (risk)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS findings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    analysis_id INT NOT NULL,
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(30) NOT NULL,
    category VARCHAR(120) NOT NULL,
    owasp VARCHAR(120) NULL,
    owasp_2021 VARCHAR(160) NULL,
    owasp_2025 VARCHAR(160) NULL,
    language VARCHAR(30) NOT NULL,
    line_number INT NOT NULL,
    evidence TEXT NOT NULL,
    impact TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    confidence VARCHAR(30) NOT NULL DEFAULT 'Medium',
    cwe VARCHAR(30) DEFAULT 'N/A',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_findings_analysis
        FOREIGN KEY (analysis_id) REFERENCES analyses(id)
        ON DELETE CASCADE,
    INDEX idx_findings_analysis_id (analysis_id),
    INDEX idx_findings_severity (severity),
    INDEX idx_findings_category (category),
    INDEX idx_findings_cwe (cwe)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
