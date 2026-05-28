import os, re, json, time, html, secrets, hashlib
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Any
from dotenv import load_dotenv
from flask import Flask, request, render_template_string, jsonify, redirect, url_for, flash, make_response
import mysql.connector

load_dotenv()
APP_NAME = "OWASP Analyzer"
DB_NAME = os.getenv("DB_NAME", "owasp_analyzer_db")
SUPPORTED_LANGUAGES = {"php", "python", "java", "javascript"}
MAX_SOURCE_SIZE = int(os.getenv("MAX_SOURCE_SIZE", "200000"))

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY") or secrets.token_hex(32)

@dataclass(frozen=True)
class Finding:
    title: str
    severity: str
    category: str
    owasp_2021: str
    owasp_2025: str
    language: str
    line: int
    evidence: str
    impact: str
    recommendation: str
    confidence: str
    cwe: str = "N/A"

class Database:
    def __init__(self):
        self.server_config = {
            "host": os.getenv("DB_HOST", "127.0.0.1"),
            "port": int(os.getenv("DB_PORT", "3306")),
            "user": os.getenv("DB_USER", "root"),
            "password": os.getenv("DB_PASSWORD", ""),
            "charset": "utf8mb4",
            "autocommit": False,
        }
        self.config = {**self.server_config, "database": DB_NAME}

    def connect_server(self):
        return mysql.connector.connect(**self.server_config)

    def connect(self):
        return mysql.connector.connect(**self.config)

    def initialize(self):
        conn = self.connect_server()
        cur = conn.cursor()
        cur.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        conn.commit(); cur.close(); conn.close()

        conn = self.connect(); cur = conn.cursor()
        cur.execute("""
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
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """)
        cur.execute("""
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
                INDEX idx_findings_analysis_id (analysis_id),
                INDEX idx_findings_severity (severity),
                INDEX idx_findings_category (category),
                INDEX idx_findings_cwe (cwe)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """)
        for table, col, definition in [
            ("analyses", "source_hash", "CHAR(64) NULL"),
            ("findings", "owasp", "VARCHAR(120) NULL"),
            ("findings", "owasp_2021", "VARCHAR(160) NULL"),
            ("findings", "owasp_2025", "VARCHAR(160) NULL"),
            ("findings", "confidence", "VARCHAR(30) NOT NULL DEFAULT 'Medium'"),
            ("findings", "cwe", "VARCHAR(30) DEFAULT 'N/A'"),
        ]:
            self.ensure_column(cur, table, col, definition)
        try:
            cur.execute("ALTER TABLE findings ADD CONSTRAINT fk_findings_analysis FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE")
        except Exception:
            pass
        conn.commit(); cur.close(); conn.close()

    def ensure_column(self, cur, table, col, definition):
        cur.execute("""
            SELECT COUNT(*) FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s AND COLUMN_NAME=%s
        """, (DB_NAME, table, col))
        if cur.fetchone()[0] == 0:
            cur.execute(f"ALTER TABLE `{table}` ADD COLUMN `{col}` {definition}")

    def ping(self):
        try:
            conn = self.connect(); conn.close()
            return True, "Online"
        except Exception as exc:
            return False, f"{type(exc).__name__}: {exc}"

    def save_analysis(self, language, source_code, score, risk, findings):
        conn = self.connect(); cur = conn.cursor()
        source_hash = hashlib.sha256(source_code.encode("utf-8", errors="ignore")).hexdigest()
        cur.execute("""
            INSERT INTO analyses (language, source_code, source_hash, risk, score, total_findings)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (language, source_code, source_hash, risk, score, len(findings)))
        analysis_id = cur.lastrowid
        for f in findings:
            cur.execute("""
                INSERT INTO findings (
                    analysis_id, title, severity, category, owasp, owasp_2021, owasp_2025,
                    language, line_number, evidence, impact, recommendation, confidence, cwe
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (
                analysis_id, f.title, f.severity, f.category, f.owasp_2021, f.owasp_2021,
                f.owasp_2025, f.language, f.line, f.evidence, f.impact, f.recommendation, f.confidence, f.cwe
            ))
        conn.commit(); cur.close(); conn.close()
        return int(analysis_id)

    def get_history(self, q="", language="", risk="", limit=100):
        clauses, params = [], []
        if q:
            clauses.append("(source_code LIKE %s OR source_hash LIKE %s)"); params += [f"%{q}%", f"%{q}%"]
        if language:
            clauses.append("language=%s"); params.append(language)
        if risk:
            clauses.append("risk=%s"); params.append(risk)
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        conn = self.connect(); cur = conn.cursor(dictionary=True)
        cur.execute(f"""
            SELECT id, language, risk, score, total_findings, source_hash, created_at
            FROM analyses {where} ORDER BY created_at DESC LIMIT %s
        """, (*params, limit))
        rows = cur.fetchall()
        for r in rows: r["created_at"] = str(r["created_at"])
        cur.close(); conn.close()
        return rows

    def get_analysis(self, analysis_id):
        conn = self.connect(); cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM analyses WHERE id=%s", (analysis_id,))
        analysis = cur.fetchone()
        findings = []
        if analysis:
            analysis["created_at"] = str(analysis["created_at"])
            cur.execute("""
                SELECT id,title,severity,category,COALESCE(owasp_2021,owasp,'N/A') AS owasp_2021,
                       COALESCE(owasp_2025,'N/A') AS owasp_2025,language,line_number,evidence,impact,
                       recommendation,confidence,cwe,created_at
                FROM findings WHERE analysis_id=%s
                ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END, line_number ASC
            """, (analysis_id,))
            findings = cur.fetchall()
            for f in findings: f["created_at"] = str(f["created_at"])
        cur.close(); conn.close()
        return analysis, findings

    def get_recent_source(self, analysis_id):
        conn = self.connect(); cur = conn.cursor(dictionary=True)
        cur.execute("SELECT language, source_code FROM analyses WHERE id=%s", (analysis_id,))
        row = cur.fetchone(); cur.close(); conn.close()
        return (row["language"], row["source_code"]) if row else None

    def delete_analysis(self, analysis_id):
        conn = self.connect(); cur = conn.cursor()
        cur.execute("DELETE FROM analyses WHERE id=%s", (analysis_id,))
        conn.commit(); cur.close(); conn.close()

    def clear_history(self):
        conn = self.connect(); cur = conn.cursor()
        cur.execute("DELETE FROM analyses")
        conn.commit(); cur.close(); conn.close()

    def stats(self):
        conn = self.connect(); cur = conn.cursor(dictionary=True)
        cur.execute("SELECT COUNT(*) total FROM analyses"); total_analyses = cur.fetchone()["total"]
        cur.execute("SELECT COUNT(*) total FROM findings"); total_findings = cur.fetchone()["total"]
        cur.execute("SELECT severity, COUNT(*) total FROM findings GROUP BY severity")
        sev = {r["severity"]: r["total"] for r in cur.fetchall()}
        cur.execute("SELECT language, COUNT(*) total FROM analyses GROUP BY language ORDER BY total DESC")
        languages = cur.fetchall()
        cur.execute("SELECT category, COUNT(*) total FROM findings GROUP BY category ORDER BY total DESC LIMIT 8")
        categories = cur.fetchall()
        cur.close(); conn.close()
        return {
            "total_analyses": total_analyses,
            "total_findings": total_findings,
            "critical": sev.get("Critical", 0),
            "high": sev.get("High", 0),
            "medium": sev.get("Medium", 0),
            "low": sev.get("Low", 0),
            "languages": languages,
            "categories": categories,
        }

class SecurityAnalyzer:
    def __init__(self):
        impact = {
            "sqli": "Pode permitir leitura, alteração ou remoção de dados e bypass de autenticação.",
            "xss": "Pode permitir execução de JavaScript no navegador, roubo de sessão ou alteração da página.",
            "cmd": "Pode permitir execução de comandos no sistema operacional com privilégios da aplicação.",
            "code": "Pode permitir execução de código arbitrário dentro do processo da aplicação.",
            "path": "Pode permitir leitura de arquivos sensíveis ou acesso fora do diretório permitido.",
            "deser": "Pode permitir manipulação de objetos, execução de código ou bypass de regras internas.",
            "crypto": "Pode expor dados sensíveis ou facilitar quebra de senhas, tokens e assinaturas.",
            "secret": "Pode expor credenciais em repositórios, logs, backups ou entregas ao cliente.",
            "auth": "Pode permitir bypass de autenticação, sessão fraca ou elevação de privilégio.",
            "misconfig": "Pode expor debug, stack traces ou comportamento inseguro.",
            "upload": "Pode permitir upload de arquivos indevidos ou execução posterior de conteúdo malicioso.",
            "ssrf": "Pode permitir que o servidor acesse recursos internos ou externos sem autorização.",
        }
        self.rules = {
            "php": [
                self.rule("SQL Injection por concatenação","Critical","Injection","A03:2021 Injection","A05:2025 Injection","CWE-89",[r"(SELECT|INSERT|UPDATE|DELETE).*(\.\s*\$_(GET|POST|REQUEST|COOKIE)|\$_(GET|POST|REQUEST|COOKIE))",r"(mysqli_query|mysql_query|pg_query)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)"],impact["sqli"],"Use prepared statements com bind de parâmetros."),
                self.rule("XSS refletido ou armazenado","High","Cross-Site Scripting","A03:2021 Injection","A05:2025 Injection","CWE-79",[r"\b(echo|print)\s+\$_(GET|POST|REQUEST|COOKIE)",r"<\?=\s*\$_(GET|POST|REQUEST|COOKIE)"],impact["xss"],"Use htmlspecialchars com ENT_QUOTES e UTF-8."),
                self.rule("Command Injection","Critical","Injection","A03:2021 Injection","A05:2025 Injection","CWE-78",[r"\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)"],impact["cmd"],"Evite shell; use APIs nativas e allowlist."),
                self.rule("Path Traversal ou LFI","High","Broken Access Control","A01:2021 Broken Access Control","A01:2025 Broken Access Control","CWE-22",[r"\b(include|require|file_get_contents|fopen|readfile)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)"],impact["path"],"Use allowlist e normalize caminhos."),
                self.rule("Desserialização insegura","Critical","Software and Data Integrity Failures","A08:2021 Software and Data Integrity Failures","A03:2025 Software Supply Chain Failures","CWE-502",[r"\bunserialize\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)"],impact["deser"],"Não desserialize dados externos."),
                self.rule("Hash inseguro","Medium","Cryptographic Failures","A02:2021 Cryptographic Failures","A04:2025 Cryptographic Failures","CWE-327",[r"\b(md5|sha1)\s*\("],impact["crypto"],"Use password_hash com Argon2id ou bcrypt."),
                self.rule("Upload inseguro","High","Unrestricted File Upload","A05:2021 Security Misconfiguration","A02:2025 Security Misconfiguration","CWE-434",[r"\bmove_uploaded_file\s*\([^)]*\$_FILES",r"\$_FILES\s*\[[^\]]+\]\s*\[\s*['\"]name['\"]"],impact["upload"],"Valide MIME real, extensão e renomeie arquivos."),
            ],
            "python": [
                self.rule("SQL Injection por interpolação","Critical","Injection","A03:2021 Injection","A05:2025 Injection","CWE-89",[r"\.execute\s*\(\s*f[\"'].*(SELECT|INSERT|UPDATE|DELETE)",r"\.execute\s*\(\s*[\"'].*(SELECT|INSERT|UPDATE|DELETE).*(\+|%)",r"\.execute\s*\([^)]*\.format\s*\("],impact["sqli"],"Use cursor.execute com parâmetros."),
                self.rule("Command Injection","Critical","Injection","A03:2021 Injection","A05:2025 Injection","CWE-78",[r"\bos\.system\s*\(",r"subprocess\.(call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True"],impact["cmd"],"Use subprocess com lista de argumentos e shell=False."),
                self.rule("Execução dinâmica perigosa","Critical","Code Injection","A03:2021 Injection","A05:2025 Injection","CWE-94",[r"\beval\s*\(",r"\bexec\s*\("],impact["code"],"Remova eval/exec e use lógica explícita."),
                self.rule("Desserialização insegura","Critical","Software and Data Integrity Failures","A08:2021 Software and Data Integrity Failures","A03:2025 Software Supply Chain Failures","CWE-502",[r"\bpickle\.(loads|load)\s*\(",r"\byaml\.load\s*\("],impact["deser"],"Use JSON ou yaml.safe_load."),
                self.rule("Path Traversal","High","Broken Access Control","A01:2021 Broken Access Control","A01:2025 Broken Access Control","CWE-22",[r"\bopen\s*\([^)]*(request\.args|request\.form|input\s*\()",r"\bsend_file\s*\([^)]*(request\.args|request\.form)"],impact["path"],"Normalize com pathlib e valide diretório base."),
                self.rule("Hash inseguro","Medium","Cryptographic Failures","A02:2021 Cryptographic Failures","A04:2025 Cryptographic Failures","CWE-327",[r"\bhashlib\.(md5|sha1)\s*\("],impact["crypto"],"Use Argon2, bcrypt ou PBKDF2 com salt."),
                self.rule("Debug habilitado","Medium","Security Misconfiguration","A05:2021 Security Misconfiguration","A02:2025 Security Misconfiguration","CWE-489",[r"\bdebug\s*=\s*True",r"\bapp\.run\s*\([^)]*debug\s*=\s*True"],impact["misconfig"],"Desative debug em produção."),
                self.rule("SSRF potencial","High","Server-Side Request Forgery","A10:2021 SSRF","A10:2025 Server-Side Request Forgery","CWE-918",[r"\brequests\.(get|post|put|delete)\s*\([^)]*(request\.args|request\.form|input\s*\()"],impact["ssrf"],"Use allowlist de domínios e bloqueie IPs privados."),
            ],
            "java": [
                self.rule("SQL Injection com Statement","Critical","Injection","A03:2021 Injection","A05:2025 Injection","CWE-89",[r"\bcreateStatement\s*\(",r"\bexecute(Query|Update)?\s*\([^)]*\+",r"(SELECT|INSERT|UPDATE|DELETE).*\+"],impact["sqli"],"Use PreparedStatement."),
                self.rule("Command Injection","Critical","Injection","A03:2021 Injection","A05:2025 Injection","CWE-78",[r"Runtime\.getRuntime\(\)\.exec\s*\(",r"new\s+ProcessBuilder\s*\([^)]*getParameter"],impact["cmd"],"Use argumentos fixos e allowlist."),
                self.rule("Desserialização insegura","Critical","Software and Data Integrity Failures","A08:2021 Software and Data Integrity Failures","A03:2025 Software Supply Chain Failures","CWE-502",[r"\bObjectInputStream\b",r"\breadObject\s*\("],impact["deser"],"Evite desserialização nativa de dados externos."),
                self.rule("Path Traversal","High","Broken Access Control","A01:2021 Broken Access Control","A01:2025 Broken Access Control","CWE-22",[r"new\s+File\s*\([^)]*getParameter",r"Paths\.get\s*\([^)]*getParameter"],impact["path"],"Normalize caminho e valide diretório base."),
                self.rule("Hash inseguro","Medium","Cryptographic Failures","A02:2021 Cryptographic Failures","A04:2025 Cryptographic Failures","CWE-327",[r"MessageDigest\.getInstance\s*\(\s*[\"'](MD5|SHA-1)[\"']\s*\)"],impact["crypto"],"Use BCrypt, Argon2 ou PBKDF2."),
                self.rule("XXE possível","High","Security Misconfiguration","A05:2021 Security Misconfiguration","A02:2025 Security Misconfiguration","CWE-611",[r"DocumentBuilderFactory\.newInstance\s*\(",r"SAXParserFactory\.newInstance\s*\("],"Pode permitir leitura de arquivos locais ou SSRF via XML.","Desabilite entidades externas e DTD."),
            ],
            "javascript": [
                self.rule("XSS por HTML dinâmico","High","Cross-Site Scripting","A03:2021 Injection","A05:2025 Injection","CWE-79",[r"\.innerHTML\s*=",r"\bdocument\.write\s*\(",r"\.insertAdjacentHTML\s*\(",r"dangerouslySetInnerHTML"],impact["xss"],"Use textContent ou sanitização confiável."),
                self.rule("SQL Injection em Node.js","Critical","Injection","A03:2021 Injection","A05:2025 Injection","CWE-89",[r"(SELECT|INSERT|UPDATE|DELETE).*(\$\{|req\.query|req\.body|\+)",r"\bquery\s*\([^)]*(req\.query|req\.body|\+)"],impact["sqli"],"Use queries parametrizadas."),
                self.rule("Command Injection","Critical","Injection","A03:2021 Injection","A05:2025 Injection","CWE-78",[r"child_process\.exec\s*\(",r"\bexec\s*\([^)]*(req\.query|req\.body|\+)",r"\bspawn\s*\([^)]*(req\.query|req\.body)"],impact["cmd"],"Use execFile/spawn com argumentos fixos."),
                self.rule("Uso perigoso de eval","Critical","Code Injection","A03:2021 Injection","A05:2025 Injection","CWE-94",[r"\beval\s*\(",r"new\s+Function\s*\("],impact["code"],"Remova eval/new Function."),
                self.rule("JWT inseguro","High","Authentication Failures","A07:2021 Identification and Authentication Failures","A07:2025 Authentication Failures","CWE-347",[r"\bjwt\.decode\s*\(",r"jsonwebtoken\.decode\s*\(",r"jwt\.verify\s*\([^,]+,\s*[\"'](secret|123|password|admin)[\"']"],impact["auth"],"Use jwt.verify, segredo forte e algoritmo fixo."),
                self.rule("Hardcoded Secret","High","Cryptographic Failures","A02:2021 Cryptographic Failures","A04:2025 Cryptographic Failures","CWE-798",[r"(secret|apiKey|apikey|token|password)\s*=\s*[\"'][^\"']{6,}[\"']",r"(SECRET|API_KEY|TOKEN|PASSWORD)\s*:\s*[\"'][^\"']{6,}[\"']"],impact["secret"],"Use variáveis de ambiente."),
                self.rule("SSRF potencial","High","Server-Side Request Forgery","A10:2021 SSRF","A10:2025 Server-Side Request Forgery","CWE-918",[r"\b(fetch|axios\.get|axios\.post|request)\s*\([^)]*(req\.query|req\.body)"],impact["ssrf"],"Use allowlist de URLs e bloqueie redes internas."),
            ],
        }
        self.generic_rules = [
            self.rule("Possível segredo hardcoded","High","Sensitive Data Exposure","A02:2021 Cryptographic Failures","A04:2025 Cryptographic Failures","CWE-798",[r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)\s*[:=]\s*[\"'][^\"']{8,}[\"']"],"Segredos no código podem vazar por repositórios.","Use variáveis de ambiente ou secret manager."),
            self.rule("Comparação fraca de autenticação","Medium","Authentication Weakness","A07:2021 Identification and Authentication Failures","A07:2025 Authentication Failures","CWE-287",[r"(?i)(user|username|login).*(==|===).*[\"']admin[\"']",r"(?i)(password|senha).*(==|===).*[\"'][^\"']+[\"']"],"Credenciais fixas podem permitir bypass.","Use autenticação centralizada e hash seguro."),
            self.rule("Comentário com TODO/FIXME de segurança","Low","Security Hygiene","A05:2021 Security Misconfiguration","A02:2025 Security Misconfiguration","CWE-546",[r"(?i)(TODO|FIXME|HACK).*(security|auth|password|token|sql|sanitize|escape)"],"Dívidas técnicas podem permanecer em produção.","Transforme em tarefa e corrija antes do deploy."),
        ]

    @staticmethod
    def rule(title, severity, category, owasp_2021, owasp_2025, cwe, patterns, impact, recommendation, confidence="High"):
        return dict(title=title, severity=severity, category=category, owasp_2021=owasp_2021, owasp_2025=owasp_2025, cwe=cwe, patterns=patterns, impact=impact, recommendation=recommendation, confidence=confidence)

    def analyze(self, source_code, language):
        language = normalize_language(language)
        findings = []
        for i, line in enumerate(source_code.splitlines(), 1):
            text = line.strip()
            if not text or (text.startswith(("//", "#", "*")) and not re.search(r"TODO|FIXME|HACK", text, re.I)):
                continue
            for rule in self.rules.get(language, []) + self.generic_rules:
                for pattern in rule["patterns"]:
                    if re.search(pattern, text, re.I):
                        findings.append(Finding(rule["title"], rule["severity"], rule["category"], rule["owasp_2021"], rule["owasp_2025"], language, i, text[:300], rule["impact"], rule["recommendation"], rule["confidence"], rule["cwe"]))
                        break
        return self.deduplicate(findings)

    @staticmethod
    def deduplicate(findings):
        seen, clean = set(), []
        order = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}
        for f in sorted(findings, key=lambda x: (order.get(x.severity, 9), x.line, x.title)):
            key = (f.title, f.line, f.evidence)
            if key not in seen:
                seen.add(key); clean.append(f)
        return clean

    @staticmethod
    def score(findings):
        weights = {"Critical": 30, "High": 20, "Medium": 10, "Low": 4}
        value = sum(weights.get(f.severity, 0) for f in findings) + min(len({f.category for f in findings}) * 3, 12)
        score = min(value, 100)
        if score >= 85: return score, "Crítico"
        if score >= 60: return score, "Alto"
        if score >= 30: return score, "Médio"
        if score > 0: return score, "Baixo"
        return score, "Sem achados relevantes"

def normalize_language(language):
    value = (language or "python").strip().lower()
    value = {"js": "javascript", "node": "javascript", "nodejs": "javascript", "py": "python"}.get(value, value)
    return value if value in SUPPORTED_LANGUAGES else "python"

def validate_source(source_code):
    if not isinstance(source_code, str): return False, "source_code deve ser texto."
    if not source_code.strip(): return False, "Cole algum código antes de analisar."
    if len(source_code.encode("utf-8", errors="ignore")) > MAX_SOURCE_SIZE: return False, f"Código excede {MAX_SOURCE_SIZE} bytes."
    return True, ""

def serialize_findings(findings, escape_evidence=False):
    result = []
    for f in findings:
        item = asdict(f)
        if escape_evidence: item["evidence"] = html.escape(item["evidence"])
        result.append(item)
    return result

def count_findings(findings):
    get = lambda f, k: getattr(f, k) if hasattr(f, k) else f.get(k)
    return {s.lower(): len([f for f in findings if get(f, "severity") == s]) for s in ["Critical", "High", "Medium", "Low"]}

def now_utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

db = Database()
analyzer = SecurityAnalyzer()
try:
    db.initialize()
except Exception as exc:
    print("Falha ao inicializar MySQL:", exc)

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cache-Control"] = "no-store"
    return response

BASE_STYLE = """
<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{ title }}</title>
<style>
:root{--bg:#070b16;--bg2:#0d1324;--panel:#11182b;--panel2:#17213a;--txt:#e8eefc;--muted:#97a3b7;--line:#2b3854;--brand:#38bdf8;--brand2:#818cf8;--crit:#fb7185;--high:#fb923c;--med:#facc15;--low:#60a5fa;--ok:#34d399;--shadow:rgba(0,0,0,.34)}
*{box-sizing:border-box}body{margin:0;min-height:100vh;font-family:Inter,system-ui,Segoe UI,Arial,sans-serif;background:radial-gradient(circle at 10% -10%,rgba(56,189,248,.22),transparent 28%),radial-gradient(circle at 80% 0%,rgba(129,140,248,.18),transparent 30%),linear-gradient(180deg,var(--bg),var(--bg2));color:var(--txt)}
a{color:var(--brand);text-decoration:none}.sidebar{border-bottom:1px solid var(--line);background:rgba(10,15,30,.86);backdrop-filter:blur(16px);position:sticky;top:0;z-index:20}.side-inner{max-width:1240px;margin:auto;padding:14px 20px;display:flex;gap:14px;align-items:center;justify-content:space-between;flex-wrap:wrap}.logo{display:flex;align-items:center;gap:12px;font-weight:950}.logo-mark{width:38px;height:38px;border-radius:14px;background:linear-gradient(135deg,var(--brand),var(--brand2))}.nav,.toolbar{display:flex;gap:8px;flex-wrap:wrap}.nav a,.btn,button{border:1px solid var(--line);background:rgba(29,41,69,.88);color:var(--txt);border-radius:12px;padding:10px 13px;font-weight:800;cursor:pointer;display:inline-flex;align-items:center;gap:8px}.nav a:hover,.btn:hover,button:hover{border-color:var(--brand)}
.wrap{max-width:1240px;margin:auto;padding:26px 20px 44px;width:100%}.hero{display:flex;justify-content:space-between;align-items:flex-end;gap:18px;flex-wrap:wrap;margin-bottom:18px}h1{margin:0;font-size:clamp(1.8rem,4vw,3.15rem);letter-spacing:-.055em}h2,h3{letter-spacing:-.03em}.muted{color:var(--muted);line-height:1.55}.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px}.card{grid-column:span 12;background:linear-gradient(180deg,rgba(17,24,43,.98),rgba(23,33,58,.96));border:1px solid var(--line);border-radius:24px;padding:18px;box-shadow:0 24px 70px var(--shadow)}
@media(min-width:880px){.s3{grid-column:span 3}.s4{grid-column:span 4}.s6{grid-column:span 6}.s8{grid-column:span 8}}
textarea,select,input{width:100%;border:1px solid var(--line);background:#060a14;color:var(--txt);border-radius:16px;padding:13px;outline:none}textarea{min-height:470px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.92rem;line-height:1.55}label{font-weight:900;display:block;margin:0 0 8px}.form-row{display:grid;grid-template-columns:1fr;gap:12px}@media(min-width:780px){.form-row{grid-template-columns:1fr 1fr 1fr}}
.stats{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}.stat{border:1px solid var(--line);border-radius:18px;padding:15px;background:rgba(0,0,0,.18);min-height:96px}.stat b{font-size:2rem}.stat small{color:var(--muted);font-weight:800}.finding{border:1px solid var(--line);border-radius:20px;padding:15px;margin:12px 0;background:rgba(0,0,0,.18)}.finding-head{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}.badge{border-radius:999px;padding:6px 10px;font-weight:950;font-size:.78rem;white-space:nowrap}.Critical{background:rgba(251,113,133,.13);color:var(--crit);border:1px solid rgba(251,113,133,.42)}.High{background:rgba(251,146,60,.12);color:var(--high);border:1px solid rgba(251,146,60,.42)}.Medium{background:rgba(250,204,21,.12);color:var(--med);border:1px solid rgba(250,204,21,.42)}.Low{background:rgba(96,165,250,.12);color:var(--low);border:1px solid rgba(96,165,250,.42)}
pre,code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}pre{white-space:pre-wrap;overflow:auto;border:1px solid var(--line);border-radius:15px;padding:13px;background:#060a14}.table{width:100%;border-collapse:collapse}.table th,.table td{padding:12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}.table th{color:var(--muted);font-size:.85rem;text-transform:uppercase}.alert{border:1px solid rgba(251,113,133,.38);background:rgba(251,113,133,.1);padding:13px;border-radius:16px;margin:12px 0}.success{border:1px solid rgba(52,211,153,.38);background:rgba(52,211,153,.08)}.health-status{display:flex;align-items:center;gap:14px;border:1px solid var(--line);border-radius:20px;padding:18px;background:rgba(0,0,0,.19)}.health-ok{border-color:rgba(52,211,153,.45);background:rgba(52,211,153,.08)}.health-error{border-color:rgba(251,113,133,.45);background:rgba(251,113,133,.08)}.pulse{width:18px;height:18px;border-radius:999px;background:var(--ok);animation:pulse 1.6s infinite}@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(52,211,153,.7)}70%{box-shadow:0 0 0 13px transparent}100%{box-shadow:0 0 0 0 transparent}}.big-number{font-size:2.8rem;font-weight:950;color:var(--brand)}.language-list,.check-grid{display:flex;flex-wrap:wrap;gap:10px}.language-pill,.check-item{border:1px solid var(--line);background:rgba(0,0,0,.14);padding:12px;border-radius:16px}.language-pill{color:var(--brand);font-weight:950}.progress{height:10px;border-radius:999px;background:#060a14;border:1px solid var(--line);overflow:hidden}.progress span{display:block;height:100%;background:linear-gradient(90deg,var(--brand),var(--brand2))}.footer{padding:28px;color:var(--muted);text-align:center}
</style></head><body><header class="sidebar"><div class="side-inner"><div class="logo"><div class="logo-mark"></div><div>{{ app_name }}</div></div><nav class="nav"><a href="{{ url_for('index') }}">Nova análise</a><a href="{{ url_for('dashboard') }}">Dashboard</a><a href="{{ url_for('history') }}">Histórico</a><a href="{{ url_for('health') }}">Health</a></nav></div></header><main class="wrap"><section class="hero"><div><h1>{{ title }}</h1><p class="muted">{{ subtitle }}</p></div></section>{% with messages=get_flashed_messages() %}{% if messages %}{% for message in messages %}<div class="alert success">{{ message }}</div>{% endfor %}{% endif %}{% endwith %}{{ body|safe }}</main><div class="footer">Analyzer educacional local. Use somente em código próprio ou autorizado.</div></body></html>
"""

INDEX_BODY = """
<form method="post"><div class="grid"><section class="card s8"><label for="source_code">Código-fonte</label><textarea id="source_code" name="source_code" spellcheck="false" placeholder="Cole aqui o código para análise...">{{ source_code }}</textarea></section><aside class="card s4"><label for="language">Linguagem</label><select id="language" name="language">{% for item in languages %}<option value="{{ item }}" {% if item == language %}selected{% endif %}>{{ item|upper }}</option>{% endfor %}</select><div class="toolbar"><button type="submit">Analisar e salvar</button><a class="btn" href="{{ url_for('index') }}">Limpar</a><a class="btn" href="{{ url_for('sample') }}">Exemplo</a></div>{% if error %}<div class="alert">{{ error }}</div>{% endif %}<h3>Resumo</h3><div class="stats"><div class="stat"><b>{{ score }}</b><br><small>Score</small></div><div class="stat"><b>{{ findings|length }}</b><br><small>Achados</small></div><div class="stat"><b>{{ critical_count }}</b><br><small>Críticos</small></div><div class="stat"><b>{{ high_count }}</b><br><small>Altos</small></div></div><h3>Risco: {{ risk }}</h3><div class="progress"><span style="width:{{ score }}%"></span></div>{% if saved_id %}<p><a href="{{ url_for('detail', analysis_id=saved_id) }}">Abrir análise salva #{{ saved_id }}</a></p>{% endif %}</aside></div></form>
<section class="card" style="margin-top:14px"><h2>Resultado</h2>{% if findings %}{% for f in findings %}<div class="finding"><div class="finding-head"><div><strong>{{ f.title }}</strong><p class="muted">Linha {{ f.line }} · {{ f.category }} · {{ f.cwe }} · Confiança {{ f.confidence }}</p></div><span class="badge {{ f.severity }}">{{ f.severity }}</span></div><pre>{{ f.evidence }}</pre><p><strong>OWASP 2021:</strong> {{ f.owasp_2021 }}</p><p><strong>OWASP 2025:</strong> {{ f.owasp_2025 }}</p><p><strong>Impacto:</strong> {{ f.impact }}</p><p><strong>Correção:</strong> {{ f.recommendation }}</p></div>{% endfor %}{% else %}<p class="muted">Nenhum achado relevante identificado.</p>{% endif %}</section>
"""
DASHBOARD_BODY = """
<section class="grid"><article class="card s3"><div class="stat"><b>{{ stats.total_analyses }}</b><br><small>Análises</small></div></article><article class="card s3"><div class="stat"><b>{{ stats.total_findings }}</b><br><small>Achados</small></div></article><article class="card s3"><div class="stat"><b>{{ stats.critical }}</b><br><small>Críticos</small></div></article><article class="card s3"><div class="stat"><b>{{ stats.high }}</b><br><small>Altos</small></div></article></section><section class="grid" style="margin-top:14px"><article class="card s6"><h2>Linguagens analisadas</h2>{% if stats.languages %}<table class="table">{% for row in stats.languages %}<tr><th>{{ row.language|upper }}</th><td>{{ row.total }}</td></tr>{% endfor %}</table>{% else %}<p class="muted">Ainda não existem análises salvas.</p>{% endif %}</article><article class="card s6"><h2>Categorias mais encontradas</h2>{% if stats.categories %}<table class="table">{% for row in stats.categories %}<tr><th>{{ row.category }}</th><td>{{ row.total }}</td></tr>{% endfor %}</table>{% else %}<p class="muted">Ainda não existem achados salvos.</p>{% endif %}</article></section>
"""
HISTORY_BODY = """
<section class="card"><h2>Filtros</h2><form method="get" class="form-row"><div><label>Busca</label><input name="q" value="{{ q }}" placeholder="hash ou trecho de código"></div><div><label>Linguagem</label><select name="language"><option value="">Todas</option>{% for item in languages %}<option value="{{ item }}" {% if item == language %}selected{% endif %}>{{ item|upper }}</option>{% endfor %}</select></div><div><label>Risco</label><select name="risk"><option value="">Todos</option>{% for item in risks %}<option value="{{ item }}" {% if item == risk %}selected{% endif %}>{{ item }}</option>{% endfor %}</select></div><div class="toolbar"><button type="submit">Filtrar</button><a class="btn" href="{{ url_for('history') }}">Limpar filtros</a><a class="btn" href="{{ url_for('clear_history') }}">Limpar histórico</a></div></form></section>
<section class="card" style="margin-top:14px"><h2>Últimas análises salvas</h2>{% if rows %}<table class="table"><thead><tr><th>ID</th><th>Linguagem</th><th>Risco</th><th>Score</th><th>Achados</th><th>Hash</th><th>Data</th><th>Ações</th></tr></thead><tbody>{% for row in rows %}<tr><td>{{ row.id }}</td><td>{{ row.language }}</td><td>{{ row.risk }}</td><td>{{ row.score }}</td><td>{{ row.total_findings }}</td><td><code>{{ row.source_hash[:12] if row.source_hash else "" }}</code></td><td>{{ row.created_at }}</td><td><a href="{{ url_for('detail', analysis_id=row.id) }}">Abrir</a> · <a href="{{ url_for('delete', analysis_id=row.id) }}">Excluir</a></td></tr>{% endfor %}</tbody></table>{% else %}<p class="muted">Nenhuma análise encontrada.</p>{% endif %}</section>
"""
DETAIL_BODY = """
<section class="grid"><article class="card s8"><h2>Código analisado</h2><p class="muted">{{ analysis.language }} · {{ analysis.created_at }} · hash <code>{{ analysis.source_hash }}</code></p><pre>{{ analysis.source_code }}</pre></article><aside class="card s4"><h2>Resumo</h2><div class="stats"><div class="stat"><b>{{ analysis.score }}</b><br><small>Score</small></div><div class="stat"><b>{{ analysis.total_findings }}</b><br><small>Achados</small></div><div class="stat"><b>{{ critical_count }}</b><br><small>Críticos</small></div><div class="stat"><b>{{ high_count }}</b><br><small>Altos</small></div></div><h3>Risco: {{ analysis.risk }}</h3><div class="progress"><span style="width:{{ analysis.score }}%"></span></div><div class="toolbar"><a class="btn" href="{{ url_for('analysis_json', analysis_id=analysis.id) }}">Ver JSON</a><a class="btn" href="{{ url_for('export_analysis', analysis_id=analysis.id) }}">Exportar</a><a class="btn" href="{{ url_for('reanalyze', analysis_id=analysis.id) }}">Reanalisar</a></div></aside></section><section class="card" style="margin-top:14px"><h2>Achados</h2>{% if findings %}{% for f in findings %}<div class="finding"><div class="finding-head"><div><strong>{{ f.title }}</strong><p class="muted">Linha {{ f.line_number }} · {{ f.category }} · {{ f.cwe }} · Confiança {{ f.confidence }}</p></div><span class="badge {{ f.severity }}">{{ f.severity }}</span></div><pre>{{ f.evidence }}</pre><p><strong>OWASP 2021:</strong> {{ f.owasp_2021 }}</p><p><strong>OWASP 2025:</strong> {{ f.owasp_2025 }}</p><p><strong>Impacto:</strong> {{ f.impact }}</p><p><strong>Correção:</strong> {{ f.recommendation }}</p></div>{% endfor %}{% else %}<p class="muted">Nenhum achado salvo.</p>{% endif %}</section>
"""
HEALTH_BODY = """
<section class="grid"><article class="card s4"><h2>Status da aplicação</h2><div class="health-status health-ok"><div class="pulse"></div><div><strong>Online</strong><p class="muted">Servidor Flask respondendo.</p></div></div></article><article class="card s4"><h2>Status do banco</h2><div class="health-status {{ db_badge }}"><div class="pulse"></div><div><strong>{{ db_status }}</strong><p class="muted">Conexão com MySQL e schema.</p></div></div></article><article class="card s4"><h2>Limite de análise</h2><div class="big-number">{{ max_kb }} KB</div><p class="muted">Tamanho máximo aceito por envio.</p></article></section>
<section class="grid" style="margin-top:14px"><article class="card s6"><h2>Linguagens suportadas</h2><div class="language-list">{% for language in languages %}<span class="language-pill">{{ language|upper }}</span>{% endfor %}</div><p class="muted">Essas linguagens são reconhecidas pelo motor de análise atual.</p></article><article class="card s6"><h2>Informações técnicas</h2><table class="table"><tr><th>Ambiente</th><td>{{ env }}</td></tr><tr><th>Host</th><td>{{ host }}</td></tr><tr><th>Porta</th><td>{{ port }}</td></tr><tr><th>Banco</th><td>{{ db_name }}</td></tr><tr><th>Horário UTC</th><td>{{ time }}</td></tr><tr><th>Endpoint JSON</th><td><a href="{{ url_for('health_json') }}">/health/json</a></td></tr></table></article></section>
<section class="card" style="margin-top:14px"><h2>Ações rápidas</h2><div class="toolbar"><a class="btn" href="{{ url_for('index') }}">Sair do Health</a><a class="btn" href="{{ url_for('dashboard') }}">Abrir Dashboard</a><a class="btn" href="{{ url_for('history') }}">Abrir Histórico</a><a class="btn" href="{{ url_for('health_json') }}">Ver JSON</a></div><p class="muted">Use “Sair do Health” para voltar direto para a tela principal, sem depender do botão voltar.</p></section>
<section class="card" style="margin-top:14px"><h2>Funções monitoradas</h2><div class="check-grid"><div class="check-item"><strong>Análise</strong><p class="muted">Motor regex carregado.</p></div><div class="check-item"><strong>Histórico</strong><p class="muted">Persistência no MySQL.</p></div><div class="check-item"><strong>Dashboard</strong><p class="muted">Resumo por severidade.</p></div><div class="check-item"><strong>API</strong><p class="muted">GET mostra documentação e POST /api/analyze analisa código.</p></div></div></section>
"""

def page(title, subtitle, body, **context):
    return render_template_string(BASE_STYLE, app_name=APP_NAME, title=title, subtitle=subtitle, body=render_template_string(body, **context))

@app.errorhandler(500)
def handle_500(error):
    return page("Erro interno", "Ocorreu uma falha no servidor. Verifique MySQL, usuário, senha e dependências.", """<section class='card'><h2>Internal Server Error</h2><p class='muted'>Abra o terminal onde está rodando python app.py para ver o erro completo.</p><p><a class='btn' href='{{ url_for('health') }}'>Abrir Health Check</a></p></section>"""), 500

SAMPLE_CODE = '''from flask import Flask, request
import subprocess
import hashlib
app = Flask(__name__)
@app.route("/user")
def user():
    user_id = request.args.get("id")
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return "ok"
@app.route("/ping")
def ping():
    host = request.args.get("host")
    subprocess.run("echo " + host, shell=True)
    return "done"
password_hash = hashlib.md5(b"admin123").hexdigest()
app.run(debug=True)
'''


@app.errorhandler(405)
def handle_405(error):
    return redirect(url_for("index"))

@app.route("/sample")
def sample():
    stats = count_findings([])
    return page("Nova análise", "Exemplo didático carregado para testar o motor.", INDEX_BODY, source_code=SAMPLE_CODE, language="python", languages=sorted(SUPPORTED_LANGUAGES), findings=[], score=0, risk="Exemplo carregado", saved_id=None, error="", critical_count=stats["critical"], high_count=stats["high"])

@app.route("/", methods=["GET", "POST"])
def index():
    source_code, language, findings, score, risk, saved_id, error = "", "python", [], 0, "Sem análise", None, ""
    if request.method == "POST":
        source_code = request.form.get("source_code", "")
        language = normalize_language(request.form.get("language", "python"))
        valid, error = validate_source(source_code)
        if valid:
            start = time.perf_counter()
            findings = analyzer.analyze(source_code, language)
            score, risk = analyzer.score(findings)
            saved_id = db.save_analysis(language, source_code, score, risk, findings)
            flash(f"Análise concluída em {round((time.perf_counter()-start)*1000,2)} ms.")
    stats = count_findings(findings)
    return page("Nova análise", "Análise estática educacional para PHP, Python, Java e JavaScript.", INDEX_BODY, source_code=source_code, language=language, languages=sorted(SUPPORTED_LANGUAGES), findings=serialize_findings(findings, True), score=score, risk=risk, saved_id=saved_id, error=error, critical_count=stats["critical"], high_count=stats["high"])

@app.route("/dashboard")
def dashboard():
    try: stats = db.stats()
    except Exception: stats = {"total_analyses":0,"total_findings":0,"critical":0,"high":0,"medium":0,"low":0,"languages":[],"categories":[]}
    return page("Dashboard", "Visão geral das análises salvas, severidades e categorias.", DASHBOARD_BODY, stats=stats)

@app.route("/history")
def history():
    q = request.args.get("q", "").strip()
    language = normalize_language(request.args.get("language", "")) if request.args.get("language") else ""
    risk = request.args.get("risk", "").strip()
    rows = db.get_history(q=q, language=language, risk=risk)
    return page("Histórico", "Consulta das análises armazenadas no MySQL.", HISTORY_BODY, rows=rows, q=q, language=language, risk=risk, languages=sorted(SUPPORTED_LANGUAGES), risks=["Crítico", "Alto", "Médio", "Baixo", "Sem achados relevantes"])

@app.route("/analysis/<int:analysis_id>")
def detail(analysis_id):
    analysis, findings = db.get_analysis(analysis_id)
    if not analysis:
        flash("Análise não encontrada."); return redirect(url_for("history"))
    stats = count_findings(findings)
    return page(f"Análise #{analysis_id}", "Detalhes do código analisado e dos achados.", DETAIL_BODY, analysis=analysis, findings=findings, critical_count=stats["critical"], high_count=stats["high"])

@app.route("/analysis/<int:analysis_id>/delete", methods=["GET", "POST"])
def delete(analysis_id):
    db.delete_analysis(analysis_id); flash(f"Análise #{analysis_id} excluída."); return redirect(url_for("history"))

@app.route("/analysis/<int:analysis_id>/json")
def analysis_json(analysis_id):
    analysis, findings = db.get_analysis(analysis_id)
    if not analysis: return jsonify({"error":"Analysis not found"}), 404
    return jsonify({"analysis": analysis, "findings": findings})

@app.route("/analysis/<int:analysis_id>/export")
def export_analysis(analysis_id):
    analysis, findings = db.get_analysis(analysis_id)
    if not analysis: return jsonify({"error":"Analysis not found"}), 404
    payload = {"exported_at": now_utc(), "app": APP_NAME, "analysis": analysis, "findings": findings}
    response = make_response(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
    response.headers["Content-Type"] = "application/json; charset=utf-8"
    response.headers["Content-Disposition"] = f"attachment; filename=owasp-analysis-{analysis_id}.json"
    return response

@app.route("/analysis/<int:analysis_id>/reanalyze")
def reanalyze(analysis_id):
    source = db.get_recent_source(analysis_id)
    if not source:
        flash("Análise não encontrada."); return redirect(url_for("history"))
    language, source_code = source
    findings = analyzer.analyze(source_code, language)
    score, risk = analyzer.score(findings)
    new_id = db.save_analysis(language, source_code, score, risk, findings)
    flash(f"Análise #{analysis_id} reanalisada e salva como #{new_id}.")
    return redirect(url_for("detail", analysis_id=new_id))

@app.route("/history/clear", methods=["GET", "POST"])
def clear_history():
    if request.args.get("confirm") != "yes":
        return page("Confirmar limpeza", "Esta ação remove todo o histórico salvo.", """<section class='card'><h2>Limpar histórico?</h2><p class='muted'>Remove análises e achados salvos. O banco continua existindo.</p><div class='toolbar'><a class='btn' href='{{ url_for('clear_history', confirm='yes') }}'>Confirmar limpeza</a><a class='btn' href='{{ url_for('history') }}'>Cancelar</a></div></section>""")
    db.clear_history(); flash("Histórico limpo com sucesso."); return redirect(url_for("history"))

@app.route("/api/analyze", methods=["GET", "POST"])
def api_analyze():
    if request.method == "GET":
        return redirect(url_for("index"))

    data = request.get_json(silent=True) or {}
    source_code = data.get("source_code", "")
    language = normalize_language(data.get("language", "python"))
    save = bool(data.get("save", True))

    valid, error = validate_source(source_code)

    if not valid:
        return jsonify({"error": error}), 400

    start = time.perf_counter()
    findings = analyzer.analyze(source_code, language)
    score, risk = analyzer.score(findings)
    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
    analysis_id = db.save_analysis(language, source_code, score, risk, findings) if save else None

    return jsonify(
        {
            "analysis_id": analysis_id,
            "language": language,
            "score": score,
            "risk": risk,
            "total_findings": len(findings),
            "elapsed_ms": elapsed_ms,
            "findings": serialize_findings(findings),
        }
    )


@app.route("/health")
def health():
    db_ok, db_status = db.ping()
    return page("Health Check", "Diagnóstico visual da aplicação, banco e configuração.", HEALTH_BODY, db_status=db_status, db_badge="health-ok" if db_ok else "health-error", max_kb=round(MAX_SOURCE_SIZE/1024,1), languages=sorted(SUPPORTED_LANGUAGES), env=os.getenv("FLASK_ENV", "development"), host=os.getenv("HOST", "127.0.0.1"), port=os.getenv("PORT", "5000"), db_name=DB_NAME, time=now_utc())

@app.route("/health/json")
def health_json():
    db_ok, db_status = db.ping()
    return jsonify({"status":"ok", "database_ok": db_ok, "database": db_status, "database_name": DB_NAME, "supported_languages": sorted(SUPPORTED_LANGUAGES), "max_source_size": MAX_SOURCE_SIZE, "time": now_utc()})

def open_browser_once(host: str, port: int) -> None:
    if os.getenv("AUTO_OPEN_BROWSER", "1") == "1":
        url_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
        threading.Timer(1.2, lambda: webbrowser.open(f"http://{url_host}:{port}")).start()


if __name__ == "__main__":
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "0") == "1"

    open_browser_once(host, port)

    app.run(
        host=host,
        port=port,
        debug=debug,
        use_reloader=False,
    )
