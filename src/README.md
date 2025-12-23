# // VALIDADOR_SEC v2.0
**Cyber Security Vulnerability Scanner**
*(Scanner de Vulnerabilidades de Segurança Cibernética)*

---

![Security](https://img.shields.io/badge/Security-Advanced-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Stable-success?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge)

## 📌 Visão Geral

O **Validador_Sec** é uma ferramenta de auditoria de segurança open-source projetada para identificar vulnerabilidades críticas em aplicações web modernas. Ele executa uma bateria de testes automatizados abrangendo desde verificações básicas de infraestrutura até explorações complexas de injeção e falhas de configuração.

O objetivo é fornecer um relatório claro e acionável para desenvolvedores e equipes de segurança (Blue/Red Teams).

---

## 🚀 Como Iniciar

A estrutura do projeto foi simplificada para facilitar o uso.

1.  **Pré-requisitos:**
    *   Python 3 instalado e adicionado ao PATH.
    *   Conexão com a internet para baixar dependências na primeira execução.

2.  **Instalação:**
    ```bash
    git clone https://seu-repo/validador_sec.git
    cd validador_sec
    pip install -r src/requirements.txt
    ```

3.  **Execução:**
    Basta clicar duas vezes no arquivo **`INICIAR.bat`** na raiz do projeto.
    *   Ele verificará a porta 5000.
    *   Iniciará o servidor Flask localmente.
    *   Abrirá automaticamente o navegador em `http://localhost:5000`.

---

## 📘 Metodologia de Testes

O scanner realiza **24+ verificações distintas**, classificadas por severidade e categoria.

### 📡 Painel de Informações Técnicas (NEW!)
Antes de cada scan, o sistema exibe métricas de conectividade:
- **IP do Servidor** - Resolução DNS
- **Latência/Response Time** - Tempo de resposta HTTP (ms)
- **DNS Resolution Time** - Velocidade de resolução (ms)
- **Server Banner** - Identificação do servidor web

### 🛡️ Infraestrutura & Redes
| Teste | Descrição | Risco |
| :--- | :--- | :--- |
| **Port Scan (Professional)** | Varredura ativa em **26 portas críticas** (FTP, SSH, Telnet, DNS, SMTP, SQL, Docker, K8s). | Identifica serviços desnecessários expostos. |
| **SSL/TLS Analysis** | Verifica a validade, emissor e data de expiração do certificado SSL. | Evita conexões inseguras e alertas de "Não Seguro". |
| **DNS Security** | Consulta registros **SPF** e **DMARC** do domínio. | Previne spoofing de e-mail e phishing. |
| **Subdomain Discovery** | Busca por subdomínios comuns (`dev`, `api`, `test`, `staging`). | Ambientes de desenvolvimento costumam ser vulneráveis. |
| **Server Version** | Identifica headers de servidores (Nginx, Apache, IIS). | Servidores desatualizados são vetores de ataque fáceis. |
| **WAF Detection** | Detecta presença de Web Application Firewalls (Cloudflare, Sucuri, etc.). | Reconhecimento de perímetro. |

### 💉 Injeção & Exploração (OWASP Top 10)
| Teste | Descrição | Risco |
| :--- | :--- | :--- |
| **SQL Injection** | Injeta aspas (`'`) e payloads em parâmetros GET para provocar erros de sintaxe SQL. | Vazamento total de banco de dados. |
| **OS Command Injection** | Tenta injetar comandos de shell (`; echo "VULN"`) em parâmetros. | **Crítico:** Controle total do servidor (RCE). |
| **XSS (Cross-Site Scripting)** | Testa reflexão de inputs perigosos (`<script>`) e analisa política CSP. | Roubo de sessão e defacement. |
| **PHP Version / CVEs** | Checa versões EOL do PHP e vulnerabilidades específicas como **CVE-2024-4577** (PHP CGI Argument Injection). | Execução remota de código (RCE). |
| **Open Redirect** | Tenta forçar redirecionamentos para sites externos maliciosos. | Phishing facilitado. |

### 🔒 Configurações de Segurança & Headers
| Teste | Descrição | Risco |
| :--- | :--- | :--- |
| **Missing Security Headers** | Verifica `HSTS`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`. | Proteção contra MITM, Sniffing e abusos de API. |
| **Clickjacking** | Testa se o site pode ser renderizado em um `<iframe>`. | Ataques de sobreposição de interface. |
| **CORS Misconfiguration** | Testa se a API permite acesso de qualquer origem (`Origin: *`) com credenciais. | Roubo de dados sensíveis por terceiros. |
| **CSRF** | Analisa heuristicamente a presença de tokens anti-CSRF em formulários. | Ações indesejadas em nome do usuário. |
| **Cookie Security** | Valida se os cookies possuem flags `Secure` e `HttpOnly`. | Roubo de cookies de sessão. |
| **Dangerous HTTP Methods** | Verifica se métodos como `PUT`, `DELETE` ou `TRACE` estão habilitados. | Upload de arquivos ou XST. |

### 🕵️‍♂️ Informação & Reconhecimento
| Teste | Descrição | Risco |
| :--- | :--- | :--- |
| **Sensitive Directories** | Fuzzing de diretórios comuns (`/admin`, `/.git`, `/backup`, `/config`). | Acesso a áreas restritas. |
| **Robots.txt Analysis** | Lê o arquivo `robots.txt` em busca de caminhos ocultos (`Disallow`). | Revelação de estrutura interna. |
| **PII Scanning** | Busca padrões de **CPF** e **E-mails** vazados no código fonte (Regex). | Violação de privacidade (LGPD). |
| **Swagger/OpenAPI** | Procura por rotas de documentação de API (`/swagger-ui.html`). | Mapeamento fácil para atacantes. |
| **Subresource Integrity (SRI)** | Verifica se scripts externos (CDNs) possuem hash de integridade. | Ataques de Supply Chain (JS malicioso injetado via CDN). |
| **Reverse Tabnabbing** | Identifica links `target="_blank"` sem `noopener noreferrer`. | Sequestro de aba (Phishing). |
| **GraphQL Introspection** | Verifica se a API GraphQL permite listagem completa do schema. | Vazamento de estrutura de dados/API. |
| **Debug Mode** | Detecta páginas de erro detalhadas (Werkzeug, Django, Laravel). | Vazamento de senhas, chaves e código fonte. |
| **Subdomain Takeover** | Identifica registros CNAME apontando para serviços inexistentes. | Sequestro de subdomínios. |

---

## 📂 Estrutura de Arquivos

```
/
├── INICIAR.bat          # Script de inicialização automática
├── README.md            # Documentação completa
└── src/                 # Código-fonte da aplicação
    ├── app.py           # Servidor Flask e Rotas
    ├── scanner.py       # Lógica de escaneamento de vulnerabilidades
    ├── reporter.py      # Gerador de relatórios PDF
    ├── requirements.txt # Dependências Python
    └── templates/       # Interface Web (HTML/CSS/JS)
```

---

## 🎨 Funcionalidades da Interface

- **📋 Checklist Completo** - Visualize todos os testes (Pass/Fail) em formato de tabela
- **📥 Exportação de Relatórios** - Download em PDF com checklist completo incluso
- **🔄 Nova Análise** - Botão para limpar cache e reiniciar análise
- **📊 Dashboard de Estatísticas** - Visualização por severidade e categoria (Metodologia OWASP/Kali)
- **🗣️ Linguagem Acessível** - Relatórios e explicações traduzidos para linguagem de negócio (CEO/Gestores)
- **🔒 Proteção por Senha** - Acesso restrito via hash SHA-256
- **🛡️ Verificação de Integridade** - Checksum automático para garantir que o código não foi alterado

---

## ⚠️ Aviso Legal

Esta ferramenta destina-se **apenas para fins educacionais e testes autorizados**. O uso do Validador_Sec contra alvos sem consentimento prévio é ilegal. Os desenvolvedores não se responsabilizam por qualquer uso indevido.

---

**Desenvolvido por Maykon Silva**
*v2.0 - 2025*
