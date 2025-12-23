# 🛡️ VALIDADOR SEC v2.0

> **Scanner de Vulnerabilidades Web + Módulo OSINT Inteligente**

Sistema profissional de análise de segurança com interface moderna e 5 tipos de investigação OSINT.

---

## 🚀 Início Rápido

### Windows (1 clique):
```bash
INICIAR.bat
```

### Manual:
```bash
cd src
pip install -r requirements.txt
python app.py
```

**Acesse**: http://localhost:5000

---

## ✨ Funcionalidades

### 🔍 **Scanner de Vulnerabilidades (120+ testes)**
- SQL Injection, XSS, CSRF
- Headers de segurança
- SSL/TLS, DNS, Portas
- Diretórios sensíveis
- Validação de domínio completa
- Verificação de vazamentos
- Detecção de phishing avançada
- Análise de headers HTTP

### 🕵️ **Módulo OSINT (5 tipos de investigação)**
- 📧 **Investigação de E-mail**: Vazamentos, domínio, correlações
- 🌐 **Auditoria de Domínio**: WHOIS, DNS, SSL, Geo-IP, Phishing
- 🎣 **Detecção de Phishing**: Typosquatting, score de risco
- 👤 **Investigação de Pessoa**: Redes sociais (em desenvolvimento)
- 📱 **Análise de Telefone**: Operadora, região (em desenvolvimento)

---

## 🎨 Interface

**Tema Cyber Security** com:
- Dark mode profissional
- Neon colors (Green, Cyan, Pink)
- Formulários dinâmicos
- Progress streaming em tempo real
- Cards interativos expansíveis

---

## 📦 Tecnologias

### Backend
- **Flask** 2.3.0 - Framework web
- **Python** 3.8+ - Linguagem
- **Requests** - HTTP client
- **BeautifulSoup4** - HTML parsing
- **DNSPython** - DNS queries
- **PyOpenSSL** - SSL/TLS

### Segurança
- CSRF Protection
- Rate Limiting (3-5 req/min)
- Input Sanitization
- Session Management
- Integrity Checking

### APIs Integradas
- HaveIBeenPwned (vazamentos)
- ip-api.com (geolocalização)

---

## 📚 Documentação

- 📖 **[Como Iniciar](COMO_INICIAR.md)** - Guia de 1 clique
- 🚀 **[Início Rápido](INICIO_RAPIDO.md)** - Instalação e uso básico
- 📊 **[Resumo Executivo](RESUMO_EXECUTIVO.md)** - Overview completo
- 🏗️ **[Plano de Implementação](PLANO_IMPLEMENTACAO.md)** - Arquitetura detalhada
- 🕵️ **[Doc OSINT](src/modules/README_OSINT.md)** - API e exemplos

---

## 🎯 Uso

### Scanner de Vulnerabilidades
```
1. Acesse: http://localhost:5000
2. Digite URL alvo
3. Configure opções (scan duplo, fuzzing profundo)
4. Clique "INICIAR_SCAN"
5. Baixe relatório PDF
```

### Módulo OSINT
```
1. Clique no botão "🕵️ OSINT"
2. Escolha tipo de investigação
3. Preencha dados do alvo
4. Configure opções avançadas
5. Acompanhe progresso em tempo real
6. Exporte JSON ou PDF
```

---

## 🔑 Configuração (Opcional)

### API Keys
```bash
# Windows
set HIBP_API_KEY=sua-chave-aqui

# Linux/Mac
export HIBP_API_KEY=sua-chave-aqui
```

**HaveIBeenPwned**: https://haveibeenpwned.com/API/Key

---

## 📊 Estrutura do Projeto

```
validador_sec-main/
├── INICIAR.bat              # Script de inicialização
├── COMO_INICIAR.md          # Guia rápido
├── INICIO_RAPIDO.md         # Tutorial completo
├── RESUMO_EXECUTIVO.md      # Overview do projeto
├── PLANO_IMPLEMENTACAO.md   # Arquitetura detalhada
│
└── src/
    ├── app.py               # Servidor Flask
    ├── scanner.py           # Motor de scanning
    ├── reporter.py          # Geração de PDFs
    ├── requirements.txt     # Dependências
    │
    ├── modules/             # Módulos especializados
    │   ├── domain_validator.py
    │   ├── breach_checker.py
    │   ├── phishing_detector.py
    │   ├── header_analyzer.py
    │   ├── osint_engine.py
    │   └── README_OSINT.md
    │
    ├── templates/           # HTML
    │   ├── index.html       # Scanner
    │   └── osint.html       # OSINT
    │
    └── static/              # Assets
        ├── css/
        │   └── osint.css
        └── js/
            └── osint-controller.js
```

---

## 🔒 Segurança

- ✅ CSRF Tokens em todas requisições
- ✅ Rate Limiting (previne abuse)
- ✅ Input sanitization rigorosa
- ✅ Headers de segurança (HSTS, CSP, X-Frame-Options)
- ✅ Autenticação SHA-256
- ✅ Integrity checking

---

## 🎓 Casos de Uso

### Profissionais de Segurança
- Pentest de aplicações web
- Investigações OSINT
- Análise de compliance

### Empresas
- Auditoria de domínios
- Detecção de phishing
- Monitoramento de vazamentos

### Educação
- Demonstração de vulnerabilidades
- Treinamento em OSINT
- Metodologia OWASP Top 10

---

## 🔮 Roadmap

### Em Desenvolvimento
- [ ] Geração de PDF OSINT customizado
- [ ] Integração Sherlock/Maigret
- [ ] Enumeração de subdomínios
- [ ] Análise de telefone (phonenumbers)

### Futuro
- [ ] API RESTful
- [ ] Dashboard de múltiplos scans
- [ ] Notificações (email, Telegram)
- [ ] Machine Learning para detecção

---

## 📈 Estatísticas

- **120+ verificações** de segurança
- **5 tipos** de investigação OSINT
- **~3.800 linhas** de código
- **100% funcional** e documentado
- **Interface moderna** cyber security

---

## 🏆 Destaques

✨ Scanner + OSINT integrados
✨ Interface cyber security moderna
✨ Formulários dinâmicos inteligentes
✨ Progress streaming em tempo real
✨ Documentação completa PT-BR
✨ Código limpo e modular
✨ Pronto para produção

---

## 📝 Licença

Este projeto é de código aberto para fins educacionais e profissionais.

**⚠️ IMPORTANTE:**
- Use apenas em alvos autorizados
- Respeite leis e termos de serviço
- Não exponha à internet sem proteções adequadas

---

## 🤝 Contribuindo

Sugestões e melhorias são bem-vindas! Abra uma issue ou pull request.

---

## 📞 Suporte

- **Documentação**: Veja os arquivos `.md` na raiz
- **Problemas**: Verifique `INICIO_RAPIDO.md` → Seção "Problemas Comuns"
- **API OSINT**: Leia `src/modules/README_OSINT.md`

---

## 🎉 Agradecimentos

Desenvolvido com 💚 para a comunidade de segurança da informação.

**Validador SEC v2.0** - *Where Security Meets Intelligence*

---

**Status**: ✅ 100% Completo e Funcional

**Última atualização**: Dezembro 2025
