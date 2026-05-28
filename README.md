# OWASP Code Analyzer

Sistema web em Python com Flask para análise estática educacional de código-fonte com foco em vulnerabilidades OWASP.

O projeto permite colar trechos de código em PHP, Python, Java ou JavaScript e identificar padrões inseguros como SQL Injection, XSS, Command Injection, Path Traversal, desserialização insegura, credenciais expostas, hashes fracos e configurações perigosas.

> Projeto criado para estudo de segurança de aplicações, revisão de código e preparação para desafios no estilo WorldSkills / CTF.

---

## Funcionalidades

- Interface web local com Flask
- Análise de código-fonte por linguagem
- Suporte para:
  - PHP
  - Python
  - Java
  - JavaScript
- Detecção de vulnerabilidades baseadas em padrões OWASP
- Classificação por severidade:
  - Critical
  - High
  - Medium
  - Low
- Score de risco da análise
- Histórico de análises salvo em MySQL
- Visualização detalhada dos achados
- API JSON para análise automatizada
- Inicialização local pelo navegador

---

## Vulnerabilidades analisadas

O sistema identifica padrões relacionados a:

- SQL Injection
- Cross-Site Scripting
- Command Injection
- Code Injection
- Path Traversal / LFI
- Insecure Deserialization
- Hardcoded Secrets
- Hash inseguro com MD5/SHA1
- Upload inseguro de arquivos
- JWT inseguro
- Debug habilitado
- Falhas simples de autenticação

---

## Tecnologias usadas

- Python
- Flask
- MySQL
- mysql-connector-python
- python-dotenv
- HTML
- CSS

---

## Estrutura do projeto

```text
owasp-analyzer/
├── app.py
├── schema.sql
├── requirements.txt
├── .env.example
├── launcher.pyw
├── instalar_dependencias.pyw
├── Iniciar_OWASP_Analyzer.vbs
├── Instalar_Dependencias.vbs
└── README.md
