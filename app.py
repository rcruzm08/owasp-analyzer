import os
import re
import html
import hashlib
from dataclasses import dataclass, asdict
from datetime import datetime
from flask import Flask, request, render_template_string, jsonify, redirect, url_for
from dotenv import load_dotenv
import mysql.connector
from mysql.connector import Error

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = hashlib.sha256(str(datetime.utcnow()).encode()).hexdigest()

@dataclass
class Finding:
    title: str
    severity: str
    category: str
    owasp: str
    language: str
    line: int
    evidence: str
    impact: str
    recommendation: str
    confidence: str

class Database:
    def __init__(self):
        self.config = {
            "host": os.getenv("DB_HOST", "127.0.0.1"),
            "port": int(os.getenv("DB_PORT", "3306")),
            "user": os.getenv("DB_USER", "root"),
            "password": os.getenv("DB_PASSWORD", ""),
            "database": os.getenv("DB_NAME", "owasp_analyzer_db"),
            "charset": "utf8mb4",
            "autocommit": False
        }

    def connect(self):
        return mysql.connector.connect(**self.config)

    def save_analysis(self, language, source_code, score, risk, findings):
        conn = None
        cursor = None

        try:
            conn = self.connect()
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO analyses (language, source_code, risk, score, total_findings)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (language, source_code, risk, score, len(findings))
            )

            analysis_id = cursor.lastrowid

            for finding in findings:
                cursor.execute(
                    """
                    INSERT INTO findings
                    (
                        analysis_id,
                        title,
                        severity,
                        category,
                        owasp,
                        language,
                        line_number,
                        evidence,
                        impact,
                        recommendation,
                        confidence
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        analysis_id,
                        finding.title,
                        finding.severity,
                        finding.category,
                        finding.owasp,
                        finding.language,
                        finding.line,
                        finding.evidence,
                        finding.impact,
                        finding.recommendation,
                        finding.confidence
                    )
                )

            conn.commit()
            return analysis_id

        except Error:
            if conn:
                conn.rollback()
            raise

        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    def get_history(self):
        conn = self.connect()
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, language, risk, score, total_findings, created_at
            FROM analyses
            ORDER BY created_at DESC
            LIMIT 50
            """
        )

        rows = cursor.fetchall()

        for row in rows:
            row["created_at"] = str(row["created_at"])

        cursor.close()
        conn.close()
        return rows

    def get_analysis(self, analysis_id):
        conn = self.connect()
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, language, source_code, risk, score, total_findings, created_at
            FROM analyses
            WHERE id = %s
            """,
            (analysis_id,)
        )

        analysis = cursor.fetchone()

        if analysis:
            analysis["created_at"] = str(analysis["created_at"])

        cursor.execute(
            """
            SELECT id, title, severity, category, owasp, language, line_number, evidence, impact, recommendation, confidence, created_at
            FROM findings
            WHERE analysis_id = %s
            ORDER BY
                CASE severity
                    WHEN 'Critical' THEN 1
                    WHEN 'High' THEN 2
                    WHEN 'Medium' THEN 3
                    WHEN 'Low' THEN 4
                    ELSE 5
                END,
                line_number ASC
            """,
            (analysis_id,)
        )

        findings = cursor.fetchall()

        for finding in findings:
            finding["created_at"] = str(finding["created_at"])

        cursor.close()
        conn.close()
        return analysis, findings

    def delete_analysis(self, analysis_id):
        conn = self.connect()
        cursor = conn.cursor()

        cursor.execute(
            """
            DELETE FROM analyses
            WHERE id = %s
            """,
            (analysis_id,)
        )

        conn.commit()
        cursor.close()
        conn.close()

class SecurityAnalyzer:
    def __init__(self):
        self.rules = {
            "php": [
                {
                    "title": "SQL Injection por concatenação",
                    "severity": "Critical",
                    "category": "Injection",
                    "owasp": "A03:2021 Injection",
                    "patterns": [
                        r"(SELECT|INSERT|UPDATE|DELETE).*(\.\s*\$_(GET|POST|REQUEST|COOKIE)|\{?\$_(GET|POST|REQUEST|COOKIE))",
                        r"mysqli_query\s*\([^,]+,\s*[^)]*\$_(GET|POST|REQUEST|COOKIE)",
                        r"mysql_query\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)"
                    ],
                    "impact": "Permite manipular consultas SQL, acessar dados não autorizados, alterar registros ou autenticar indevidamente.",
                    "recommendation": "Use prepared statements com bind de parâmetros e validação de tipo.",
                    "confidence": "High"
                },
                {
                    "title": "XSS refletido ou armazenado",
                    "severity": "High",
                    "category": "Cross-Site Scripting",
                    "owasp": "A03:2021 Injection",
                    "patterns": [
                        r"echo\s+\$_(GET|POST|REQUEST|COOKIE)",
                        r"print\s+\$_(GET|POST|REQUEST|COOKIE)",
                        r"<\?=\s*\$_(GET|POST|REQUEST|COOKIE)"
                    ],
                    "impact": "Permite executar JavaScript no navegador da vítima, roubar sessões ou alterar conteúdo da página.",
                    "recommendation": "Use htmlspecialchars com ENT_QUOTES e UTF-8 antes de exibir dados do usuário.",
                    "confidence": "High"
                },
                {
                    "title": "Command Injection",
                    "severity": "Critical",
                    "category": "Injection",
                    "owasp": "A03:2021 Injection",
                    "patterns": [
                        r"(system|exec|shell_exec|passthru|popen|proc_open)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)"
                    ],
                    "impact": "Permite executar comandos no sistema operacional com privilégios da aplicação.",
                    "recommendation": "Evite shell. Use APIs seguras, allowlist estrita e escapes específicos quando inevitável.",
                    "confidence": "High"
                },
                {
                    "title": "Path Traversal ou LFI",
                    "severity": "High",
                    "category": "File Inclusion",
                    "owasp": "A01:2021 Broken Access Control",
                    "patterns": [
                        r"(include|require|include_once|require_once)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)",
                        r"(readfile|file_get_contents|fopen)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)"
                    ],
                    "impact": "Permite ler arquivos sensíveis ou incluir arquivos indevidos no servidor.",
                    "recommendation": "Use allowlist de arquivos válidos, normalize caminhos e bloqueie ../ e caminhos absolutos.",
                    "confidence": "High"
                },
                {
                    "title": "Desserialização insegura",
                    "severity": "Critical",
                    "category": "Insecure Deserialization",
                    "owasp": "A08:2021 Software and Data Integrity Failures",
                    "patterns": [
                        r"unserialize\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)"
                    ],
                    "impact": "Pode permitir execução de código, manipulação de objetos ou bypass de lógica.",
                    "recommendation": "Não desserialize dados controlados pelo usuário. Use JSON e validação de esquema.",
                    "confidence": "High"
                },
                {
                    "title": "Hash inseguro para senha ou token",
                    "severity": "Medium",
                    "category": "Cryptographic Failure",
                    "owasp": "A02:2021 Cryptographic Failures",
                    "patterns": [
                        r"\b(md5|sha1)\s*\("
                    ],
                    "impact": "Hashes fracos podem ser quebrados por força bruta ou rainbow tables.",
                    "recommendation": "Use password_hash com PASSWORD_BCRYPT ou PASSWORD_ARGON2ID.",
                    "confidence": "Medium"
                },
                {
                    "title": "Upload de arquivo inseguro",
                    "severity": "High",
                    "category": "Unrestricted File Upload",
                    "owasp": "A05:2021 Security Misconfiguration",
                    "patterns": [
                        r"move_uploaded_file\s*\([^)]*\$_FILES",
                        r"\$_FILES\s*\[[^\]]+\]\s*\[\s*['\"]name['\"]\s*\]"
                    ],
                    "impact": "Pode permitir upload de arquivos executáveis, webshells ou sobrescrita de arquivos.",
                    "recommendation": "Valide MIME real, extensão, tamanho, renomeie arquivos e armazene fora da raiz pública.",
                    "confidence": "Medium"
                }
            ],
            "python": [
                {
                    "title": "SQL Injection por interpolação",
                    "severity": "Critical",
                    "category": "Injection",
                    "owasp": "A03:2021 Injection",
                    "patterns": [
                        r"execute\s*\(\s*f[\"'].*(SELECT|INSERT|UPDATE|DELETE)",
                        r"execute\s*\(\s*[\"'].*(SELECT|INSERT|UPDATE|DELETE).*(\+|%)",
                        r"(SELECT|INSERT|UPDATE|DELETE).*\{.*\}",
                        r"(SELECT|INSERT|UPDATE|DELETE).*%s"
                    ],
                    "impact": "Permite manipular consultas SQL e acessar ou alterar dados indevidamente.",
                    "recommendation": "Use queries parametrizadas do driver do banco de dados.",
                    "confidence": "High"
                },
                {
                    "title": "Command Injection",
                    "severity": "Critical",
                    "category": "Injection",
                    "owasp": "A03:2021 Injection",
                    "patterns": [
                        r"os\.system\s*\(",
                        r"subprocess\.(call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True",
                        r"commands\.getoutput\s*\("
                    ],
                    "impact": "Permite execução de comandos no sistema operacional.",
                    "recommendation": "Use subprocess com lista de argumentos, shell=False e validação por allowlist.",
                    "confidence": "High"
                },
                {
                    "title": "Execução dinâmica perigosa",
                    "severity": "Critical",
                    "category": "Code Injection",
                    "owasp": "A03:2021 Injection",
                    "patterns": [
                        r"\beval\s*\(",
                        r"\bexec\s*\("
                    ],
                    "impact": "Permite executar código arbitrário caso a entrada seja controlada pelo usuário.",
                    "recommendation": "Remova eval/exec. Use parsers seguros, estruturas condicionais ou mapeamento de funções permitidas.",
                    "confidence": "High"
                },
                {
                    "title": "Desserialização insegura",
                    "severity": "Critical",
                    "category": "Insecure Deserialization",
                    "owasp": "A08:2021 Software and Data Integrity Failures",
                    "patterns": [
                        r"pickle\.loads\s*\(",
                        r"pickle\.load\s*\(",
                        r"yaml\.load\s*\("
                    ],
                    "impact": "Pode permitir execução de código ou criação de objetos maliciosos.",
                    "recommendation": "Evite pickle com dados externos. Use json e yaml.safe_load quando aplicável.",
                    "confidence": "High"
                },
                {
                    "title": "Path Traversal",
                    "severity": "High",
                    "category": "Broken Access Control",
                    "owasp": "A01:2021 Broken Access Control",
                    "patterns": [
                        r"open\s*\([^)]*(request\.args|request\.form|input\s*\()",
                        r"send_file\s*\([^)]*(request\.args|request\.form)",
                        r"send_from_directory\s*\([^)]*(request\.args|request\.form)"
                    ],
                    "impact": "Permite leitura ou exposição de arquivos fora do diretório esperado.",
                    "recommendation": "Normalize caminhos, use allowlist e bloqueie diretórios superiores.",
                    "confidence": "Medium"
                },
                {
                    "title": "Hash inseguro",
                    "severity": "Medium",
                    "category": "Cryptographic Failure",
                    "owasp": "A02:2021 Cryptographic Failures",
                    "patterns": [
                        r"hashlib\.(md5|sha1)\s*\("
                    ],
                    "impact": "Pode facilitar quebra de senhas ou tokens.",
                    "recommendation": "Use bcrypt, argon2 ou PBKDF2 com salt e custo adequado.",
                    "confidence": "Medium"
                },
                {
                    "title": "Debug habilitado",
                    "severity": "Medium",
                    "category": "Security Misconfiguration",
                    "owasp": "A05:2021 Security Misconfiguration",
                    "patterns": [
                        r"debug\s*=\s*True",
                        r"app\.run\s*\([^)]*debug\s*=\s*True"
                    ],
                    "impact": "Pode expor stack traces, variáveis internas e console interativo.",
                    "recommendation": "Desative debug em produção e use logs controlados.",
                    "confidence": "High"
                }
            ],
            "java": [
                {
                    "title": "SQL Injection com Statement",
                    "severity": "Critical",
                    "category": "Injection",
                    "owasp": "A03:2021 Injection",
                    "patterns": [
                        r"createStatement\s*\(",
                        r"execute(Query|Update)?\s*\([^)]*\+",
                        r"(SELECT|INSERT|UPDATE|DELETE).*\+"
                    ],
                    "impact": "Permite manipular consultas SQL e comprometer dados.",
                    "recommendation": "Use PreparedStatement com parâmetros tipados.",
                    "confidence": "High"
                },
                {
                    "title": "Command Injection",
                    "severity": "Critical",
                    "category": "Injection",
                    "owasp": "A03:2021 Injection",
                    "patterns": [
                        r"Runtime\.getRuntime\(\)\.exec\s*\(",
                        r"new\s+ProcessBuilder\s*\([^)]*getParameter"
                    ],
                    "impact": "Permite executar comandos no sistema operacional.",
                    "recommendation": "Evite execução de comandos. Use ProcessBuilder com argumentos fixos e allowlist.",
                    "confidence": "High"
                },
                {
                    "title": "Desserialização insegura",
                    "severity": "Critical",
                    "category": "Insecure Deserialization",
                    "owasp": "A08:2021 Software and Data Integrity Failures",
                    "patterns": [
                        r"ObjectInputStream",
                        r"readObject\s*\("
                    ],
                    "impact": "Pode permitir execução de código ou manipulação de objetos.",
                    "recommendation": "Evite desserialização nativa com dados externos. Use filtros de classe e formatos seguros.",
                    "confidence": "High"
                },
                {
                    "title": "Path Traversal",
                    "severity": "High",
                    "category": "Broken Access Control",
                    "owasp": "A01:2021 Broken Access Control",
                    "patterns": [
                        r"new\s+File\s*\([^)]*getParameter",
                        r"Paths\.get\s*\([^)]*getParameter"
                    ],
                    "impact": "Permite acessar arquivos fora do caminho permitido.",
                    "recommendation": "Normalize o caminho, valide base directory e use allowlist.",
                    "confidence": "Medium"
                },
                {
                    "title": "Hash inseguro",
                    "severity": "Medium",
                    "category": "Cryptographic Failure",
                    "owasp": "A02:2021 Cryptographic Failures",
                    "patterns": [
                        r"MessageDigest\.getInstance\s*\(\s*[\"'](MD5|SHA-1)[\"']\s*\)"
                    ],
                    "impact": "Algoritmos fracos podem ser quebrados com baixo custo.",
                    "recommendation": "Use BCrypt, Argon2 ou PBKDF2 para senhas.",
                    "confidence": "High"
                }
            ],
            "javascript": [
                {
                    "title": "XSS por innerHTML",
                    "severity": "High",
                    "category": "Cross-Site Scripting",
                    "owasp": "A03:2021 Injection",
                    "patterns": [
                        r"\.innerHTML\s*=",
                        r"document\.write\s*\(",
                        r"\.insertAdjacentHTML\s*\("
                    ],
                    "impact": "Permite execução de JavaScript no navegador da vítima.",
                    "recommendation": "Use textContent, sanitização confiável e templates com escaping.",
                    "confidence": "High"
                },
                {
                    "title": "SQL Injection em Node.js",
                    "severity": "Critical",
                    "category": "Injection",
                    "owasp": "A03:2021 Injection",
                    "patterns": [
                        r"(SELECT|INSERT|UPDATE|DELETE).*(\$\{|req\.query|req\.body|\+)",
                        r"query\s*\([^)]*(req\.query|req\.body|\+)"
                    ],
                    "impact": "Permite manipular consultas SQL e acessar ou alterar dados.",
                    "recommendation": "Use queries parametrizadas e validação de entrada.",
                    "confidence": "High"
                },
                {
                    "title": "Command Injection",
                    "severity": "Critical",
                    "category": "Injection",
                    "owasp": "A03:2021 Injection",
                    "patterns": [
                        r"child_process\.exec\s*\(",
                        r"\bexec\s*\([^)]*(req\.query|req\.body|\+)",
                        r"\bspawn\s*\([^)]*(req\.query|req\.body)"
                    ],
                    "impact": "Permite execução de comandos no sistema operacional.",
                    "recommendation": "Use execFile/spawn com argumentos fixos e validação por allowlist.",
                    "confidence": "High"
                },
                {
                    "title": "Uso perigoso de eval",
                    "severity": "Critical",
                    "category": "Code Injection",
                    "owasp": "A03:2021 Injection",
                    "patterns": [
                        r"\beval\s*\(",
                        r"new\s+Function\s*\("
                    ],
                    "impact": "Permite execução de código arbitrário.",
                    "recommendation": "Remova eval/new Function e substitua por lógica explícita.",
                    "confidence": "High"
                },
                {
                    "title": "JWT inseguro",
                    "severity": "High",
                    "category": "Identification and Authentication Failures",
                    "owasp": "A07:2021 Identification and Authentication Failures",
                    "patterns": [
                        r"jwt\.decode\s*\(",
                        r"jwt\.verify\s*\([^,]+,\s*[\"'](secret|123|password|admin)[\"']",
                        r"jsonwebtoken\.decode\s*\("
                    ],
                    "impact": "Pode permitir bypass de autenticação ou uso de tokens adulterados.",
                    "recommendation": "Use jwt.verify, segredo forte via variável de ambiente, algoritmo fixo e expiração.",
                    "confidence": "High"
                },
                {
                    "title": "Hardcoded Secret",
                    "severity": "High",
                    "category": "Cryptographic Failure",
                    "owasp": "A02:2021 Cryptographic Failures",
                    "patterns": [
                        r"(secret|apiKey|apikey|token|password)\s*=\s*[\"'][^\"']{6,}[\"']",
                        r"(SECRET|API_KEY|TOKEN|PASSWORD)\s*:\s*[\"'][^\"']{6,}[\"']"
                    ],
                    "impact": "Credenciais expostas podem ser usadas para acesso indevido a sistemas externos.",
                    "recommendation": "Use variáveis de ambiente e cofres de segredo.",
                    "confidence": "Medium"
                }
            ]
        }

        self.generic_rules = [
            {
                "title": "Possível segredo hardcoded",
                "severity": "High",
                "category": "Sensitive Data Exposure",
                "owasp": "A02:2021 Cryptographic Failures",
                "patterns": [
                    r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)\s*[:=]\s*[\"'][^\"']{8,}[\"']",
                    r"(?i)(aws_access_key_id|aws_secret_access_key)\s*[:=]\s*[\"'][^\"']+[\"']"
                ],
                "impact": "Segredos no código podem vazar por repositórios, logs ou backups.",
                "recommendation": "Remova segredos do código e use variáveis de ambiente ou secret manager.",
                "confidence": "Medium"
            },
            {
                "title": "Comparação fraca de autenticação",
                "severity": "Medium",
                "category": "Authentication Weakness",
                "owasp": "A07:2021 Identification and Authentication Failures",
                "patterns": [
                    r"(?i)(user|username|login).*(==|===).*[\"']admin[\"']",
                    r"(?i)(password|senha).*(==|===).*[\"'][^\"']+[\"']"
                ],
                "impact": "Credenciais fixas ou comparações simples podem permitir bypass ou exposição de autenticação.",
                "recommendation": "Use autenticação centralizada, hash seguro de senha e controle de sessão.",
                "confidence": "Medium"
            }
        ]

    def analyze(self, source_code, language):
        findings = []
        lines = source_code.splitlines()
        active_rules = self.rules.get(language, []) + self.generic_rules

        for index, line in enumerate(lines, start=1):
            stripped = line.strip()

            if not stripped:
                continue

            for rule in active_rules:
                for pattern in rule["patterns"]:
                    if re.search(pattern, stripped, re.IGNORECASE):
                        findings.append(
                            Finding(
                                title=rule["title"],
                                severity=rule["severity"],
                                category=rule["category"],
                                owasp=rule["owasp"],
                                language=language,
                                line=index,
                                evidence=stripped[:250],
                                impact=rule["impact"],
                                recommendation=rule["recommendation"],
                                confidence=rule["confidence"]
                            )
                        )
                        break

        return self.reduce_duplicates(findings)

    def reduce_duplicates(self, findings):
        seen = set()
        clean = []

        for finding in findings:
            key = (finding.title, finding.line, finding.evidence)

            if key not in seen:
                seen.add(key)
                clean.append(finding)

        return clean

    def score(self, findings):
        weights = {
            "Critical": 30,
            "High": 20,
            "Medium": 10,
            "Low": 5
        }

        total = sum(weights.get(f.severity, 0) for f in findings)

        if total >= 90:
            risk = "Crítico"
        elif total >= 60:
            risk = "Alto"
        elif total >= 30:
            risk = "Médio"
        elif total > 0:
            risk = "Baixo"
        else:
            risk = "Sem achados relevantes"

        return min(total, 100), risk

db = Database()
analyzer = SecurityAnalyzer()

BASE_STYLE = """
<style>
:root {
    --bg: #0f172a;
    --panel: #111827;
    --panel2: #1f2937;
    --text: #e5e7eb;
    --muted: #9ca3af;
    --border: #374151;
    --critical: #ef4444;
    --high: #f97316;
    --medium: #eab308;
    --low: #22c55e;
    --accent: #38bdf8;
}

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background: radial-gradient(circle at top, #1e293b 0, #0f172a 45%, #020617 100%);
    color: var(--text);
    font-family: Arial, Helvetica, sans-serif;
}

header {
    padding: 24px;
    border-bottom: 1px solid var(--border);
    background: rgba(15, 23, 42, 0.9);
    position: sticky;
    top: 0;
    z-index: 10;
}

h1 {
    margin: 0;
    font-size: 25px;
}

a {
    color: var(--accent);
    text-decoration: none;
}

main {
    max-width: 1450px;
    margin: 0 auto;
    padding: 24px;
}

.nav {
    display: flex;
    gap: 14px;
    margin-top: 10px;
    font-size: 14px;
}

.grid {
    display: grid;
    grid-template-columns: 1.1fr 0.9fr;
    gap: 18px;
}

.card {
    background: rgba(17, 24, 39, 0.94);
    border: 1px solid var(--border);
    border-radius: 18px;
    overflow: hidden;
    box-shadow: 0 18px 55px rgba(0, 0, 0, .25);
}

.card-header {
    padding: 17px 20px;
    border-bottom: 1px solid var(--border);
    background: rgba(31, 41, 55, .76);
    display: flex;
    justify-content: space-between;
    gap: 12px;
    align-items: center;
}

.card-title {
    font-weight: 800;
}

.card-body {
    padding: 20px;
}

textarea {
    width: 100%;
    min-height: 540px;
    resize: vertical;
    border-radius: 14px;
    border: 1px solid var(--border);
    background: #020617;
    color: #e5e7eb;
    padding: 16px;
    font-family: Consolas, monospace;
    font-size: 14px;
    line-height: 1.5;
    outline: none;
}

pre {
    white-space: pre-wrap;
    word-break: break-word;
    background: #020617;
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 16px;
    font-family: Consolas, monospace;
    font-size: 13px;
    line-height: 1.5;
    overflow: auto;
}

select, button {
    border-radius: 12px;
    padding: 11px 13px;
    outline: none;
}

select {
    background: #020617;
    color: var(--text);
    border: 1px solid var(--border);
}

button {
    border: 0;
    background: linear-gradient(135deg, #0ea5e9, #2563eb);
    color: white;
    cursor: pointer;
    font-weight: 800;
}

.danger {
    background: linear-gradient(135deg, #ef4444, #991b1b);
}

.form-row {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    align-items: center;
}

.stats {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 10px;
}

.stat {
    background: #020617;
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 14px;
}

.stat-value {
    font-size: 25px;
    font-weight: 900;
}

.stat-label {
    color: var(--muted);
    font-size: 12px;
    margin-top: 4px;
}

.finding {
    border: 1px solid var(--border);
    border-radius: 16px;
    margin-bottom: 14px;
    overflow: hidden;
    background: #020617;
}

.finding-top {
    display: flex;
    justify-content: space-between;
    gap: 14px;
    padding: 14px 16px;
    border-bottom: 1px solid var(--border);
    background: rgba(31, 41, 55, .62);
}

.finding-title {
    font-weight: 900;
}

.meta {
    color: var(--muted);
    font-size: 12px;
    margin-top: 5px;
}

.badge {
    border-radius: 999px;
    padding: 6px 10px;
    font-size: 12px;
    font-weight: 900;
    color: #020617;
    height: fit-content;
    white-space: nowrap;
}

.Critical {
    background: var(--critical);
}

.High {
    background: var(--high);
}

.Medium {
    background: var(--medium);
}

.Low {
    background: var(--low);
}

.finding-body {
    padding: 16px;
    display: grid;
    gap: 12px;
}

.block {
    border-left: 3px solid var(--accent);
    padding-left: 12px;
}

.block strong {
    display: block;
    margin-bottom: 5px;
    font-size: 13px;
}

code {
    display: block;
    white-space: pre-wrap;
    word-break: break-word;
    background: #111827;
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 10px;
    color: #f8fafc;
    font-family: Consolas, monospace;
    font-size: 13px;
}

table {
    width: 100%;
    border-collapse: collapse;
}

th, td {
    border-bottom: 1px solid var(--border);
    padding: 13px;
    text-align: left;
    font-size: 14px;
}

th {
    color: var(--muted);
    font-size: 12px;
    text-transform: uppercase;
}

.empty {
    color: var(--muted);
    text-align: center;
    padding: 35px 10px;
}

@media (max-width: 950px) {
    .grid {
        grid-template-columns: 1fr;
    }

    .stats {
        grid-template-columns: repeat(2, 1fr);
    }
}
</style>
"""

INDEX_TEMPLATE = """
<!doctype html>
<html lang="pt-br">
<head>
<meta charset="utf-8">
<title>OWASP Analyzer</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
""" + BASE_STYLE + """
</head>
<body>
<header>
    <h1>OWASP Code Analyzer</h1>
    <div class="nav">
        <a href="/">Nova análise</a>
        <a href="/history">Histórico</a>
    </div>
</header>

<main>
    <form method="post" class="grid">
        <section class="card">
            <div class="card-header">
                <div class="card-title">Código-fonte</div>
                <div class="form-row">
                    <select name="language">
                        <option value="php" {% if language == "php" %}selected{% endif %}>PHP</option>
                        <option value="python" {% if language == "python" %}selected{% endif %}>Python</option>
                        <option value="java" {% if language == "java" %}selected{% endif %}>Java</option>
                        <option value="javascript" {% if language == "javascript" %}selected{% endif %}>JavaScript</option>
                    </select>
                    <button type="submit">Analisar e salvar</button>
                </div>
            </div>
            <div class="card-body">
                <textarea name="source_code" spellcheck="false">{{ source_code }}</textarea>
            </div>
        </section>

        <section class="card">
            <div class="card-header">
                <div class="card-title">Resultado</div>
                <strong>{{ risk }}</strong>
            </div>
            <div class="card-body">
                <div class="stats">
                    <div class="stat">
                        <div class="stat-value">{{ score }}</div>
                        <div class="stat-label">Score</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{{ findings|length }}</div>
                        <div class="stat-label">Achados</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{{ critical_count }}</div>
                        <div class="stat-label">Críticos</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{{ high_count }}</div>
                        <div class="stat-label">Altos</div>
                    </div>
                </div>

                <div style="margin-top:18px">
                    {% if saved_id %}
                        <div class="finding">
                            <div class="finding-body">
                                <div class="block">
                                    <strong>Análise salva</strong>
                                    <div>ID {{ saved_id }} · <a href="/analysis/{{ saved_id }}">abrir detalhes</a></div>
                                </div>
                            </div>
                        </div>
                    {% endif %}

                    {% if findings %}
                        {% for f in findings %}
                            <div class="finding">
                                <div class="finding-top">
                                    <div>
                                        <div class="finding-title">{{ f.title }}</div>
                                        <div class="meta">Linha {{ f.line }} · {{ f.owasp }} · Confiança {{ f.confidence }}</div>
                                    </div>
                                    <div class="badge {{ f.severity }}">{{ f.severity }}</div>
                                </div>
                                <div class="finding-body">
                                    <div class="block">
                                        <strong>Evidência</strong>
                                        <code>{{ f.evidence }}</code>
                                    </div>
                                    <div class="block">
                                        <strong>Impacto</strong>
                                        <div>{{ f.impact }}</div>
                                    </div>
                                    <div class="block">
                                        <strong>Correção recomendada</strong>
                                        <div>{{ f.recommendation }}</div>
                                    </div>
                                </div>
                            </div>
                        {% endfor %}
                    {% else %}
                        <div class="empty">Nenhum achado relevante identificado.</div>
                    {% endif %}
                </div>
            </div>
        </section>
    </form>
</main>
</body>
</html>
"""

HISTORY_TEMPLATE = """
<!doctype html>
<html lang="pt-br">
<head>
<meta charset="utf-8">
<title>Histórico</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
""" + BASE_STYLE + """
</head>
<body>
<header>
    <h1>Histórico de análises</h1>
    <div class="nav">
        <a href="/">Nova análise</a>
        <a href="/history">Histórico</a>
    </div>
</header>

<main>
    <section class="card">
        <div class="card-header">
            <div class="card-title">Últimas análises salvas</div>
        </div>
        <div class="card-body">
            {% if rows %}
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Linguagem</th>
                            <th>Risco</th>
                            <th>Score</th>
                            <th>Achados</th>
                            <th>Data</th>
                            <th>Ações</th>
                        </tr>
                    </thead>
                    <tbody>
                    {% for row in rows %}
                        <tr>
                            <td>{{ row.id }}</td>
                            <td>{{ row.language }}</td>
                            <td>{{ row.risk }}</td>
                            <td>{{ row.score }}</td>
                            <td>{{ row.total_findings }}</td>
                            <td>{{ row.created_at }}</td>
                            <td>
                                <a href="/analysis/{{ row.id }}">Abrir</a>
                                |
                                <a href="/analysis/{{ row.id }}/delete">Excluir</a>
                            </td>
                        </tr>
                    {% endfor %}
                    </tbody>
                </table>
            {% else %}
                <div class="empty">Nenhuma análise salva.</div>
            {% endif %}
        </div>
    </section>
</main>
</body>
</html>
"""

DETAIL_TEMPLATE = """
<!doctype html>
<html lang="pt-br">
<head>
<meta charset="utf-8">
<title>Detalhes da análise</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
""" + BASE_STYLE + """
</head>
<body>
<header>
    <h1>Análise #{{ analysis.id }}</h1>
    <div class="nav">
        <a href="/">Nova análise</a>
        <a href="/history">Histórico</a>
        <a href="/analysis/{{ analysis.id }}/json">JSON</a>
    </div>
</header>

<main>
    <div class="grid">
        <section class="card">
            <div class="card-header">
                <div class="card-title">Código analisado</div>
                <strong>{{ analysis.language }}</strong>
            </div>
            <div class="card-body">
                <pre>{{ analysis.source_code }}</pre>
            </div>
        </section>

        <section class="card">
            <div class="card-header">
                <div class="card-title">Achados</div>
                <strong>{{ analysis.risk }} · {{ analysis.score }}</strong>
            </div>
            <div class="card-body">
                <div class="stats">
                    <div class="stat">
                        <div class="stat-value">{{ analysis.score }}</div>
                        <div class="stat-label">Score</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{{ analysis.total_findings }}</div>
                        <div class="stat-label">Achados</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{{ critical_count }}</div>
                        <div class="stat-label">Críticos</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{{ high_count }}</div>
                        <div class="stat-label">Altos</div>
                    </div>
                </div>

                <div style="margin-top:18px">
                    {% if findings %}
                        {% for f in findings %}
                            <div class="finding">
                                <div class="finding-top">
                                    <div>
                                        <div class="finding-title">{{ f.title }}</div>
                                        <div class="meta">Linha {{ f.line_number }} · {{ f.owasp }} · Confiança {{ f.confidence }}</div>
                                    </div>
                                    <div class="badge {{ f.severity }}">{{ f.severity }}</div>
                                </div>
                                <div class="finding-body">
                                    <div class="block">
                                        <strong>Evidência</strong>
                                        <code>{{ f.evidence }}</code>
                                    </div>
                                    <div class="block">
                                        <strong>Impacto</strong>
                                        <div>{{ f.impact }}</div>
                                    </div>
                                    <div class="block">
                                        <strong>Correção recomendada</strong>
                                        <div>{{ f.recommendation }}</div>
                                    </div>
                                </div>
                            </div>
                        {% endfor %}
                    {% else %}
                        <div class="empty">Nenhum achado salvo.</div>
                    {% endif %}
                </div>
            </div>
        </section>
    </div>
</main>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    source_code = ""
    language = "python"
    findings = []
    score = 0
    risk = "Sem análise"
    saved_id = None

    if request.method == "POST":
        source_code = request.form.get("source_code", "")
        language = request.form.get("language", "python")
        findings = analyzer.analyze(source_code, language)
        score, risk = analyzer.score(findings)
        saved_id = db.save_analysis(language, source_code, score, risk, findings)

    safe_findings = []

    for f in findings:
        item = asdict(f)
        item["evidence"] = html.escape(item["evidence"])
        safe_findings.append(item)

    critical_count = len([f for f in findings if f.severity == "Critical"])
    high_count = len([f for f in findings if f.severity == "High"])

    return render_template_string(
        INDEX_TEMPLATE,
        source_code=source_code,
        language=language,
        findings=safe_findings,
        score=score,
        risk=risk,
        saved_id=saved_id,
        critical_count=critical_count,
        high_count=high_count
    )

@app.route("/history")
def history():
    rows = db.get_history()

    return render_template_string(
        HISTORY_TEMPLATE,
        rows=rows
    )

@app.route("/analysis/<int:analysis_id>")
def detail(analysis_id):
    analysis, findings = db.get_analysis(analysis_id)

    if not analysis:
        return redirect(url_for("history"))

    critical_count = len([f for f in findings if f["severity"] == "Critical"])
    high_count = len([f for f in findings if f["severity"] == "High"])

    return render_template_string(
        DETAIL_TEMPLATE,
        analysis=analysis,
        findings=findings,
        critical_count=critical_count,
        high_count=high_count
    )

@app.route("/analysis/<int:analysis_id>/delete")
def delete(analysis_id):
    db.delete_analysis(analysis_id)
    return redirect(url_for("history"))

@app.route("/analysis/<int:analysis_id>/json")
def analysis_json(analysis_id):
    analysis, findings = db.get_analysis(analysis_id)

    if not analysis:
        return jsonify({"error": "Analysis not found"}), 404

    return jsonify({
        "analysis": analysis,
        "findings": findings
    })

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json(silent=True) or {}
    source_code = data.get("source_code", "")
    language = data.get("language", "python")
    save = bool(data.get("save", True))

    findings = analyzer.analyze(source_code, language)
    score, risk = analyzer.score(findings)
    analysis_id = None

    if save:
        analysis_id = db.save_analysis(language, source_code, score, risk, findings)

    return jsonify({
        "analysis_id": analysis_id,
        "language": language,
        "score": score,
        "risk": risk,
        "total_findings": len(findings),
        "findings": [asdict(f) for f in findings]
    })

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)