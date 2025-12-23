# 🚀 GUIA DE INÍCIO RÁPIDO - Validador SEC v2.0

## ⚡ Instalação Rápida

### 1. Instalar Dependências

```bash
cd src
pip install -r requirements.txt
```

### 2. Iniciar o Sistema

**Windows:**
```bash
# Usar o script INICIAR.bat na raiz do projeto
INICIAR.bat
```

**Ou manualmente:**
```bash
cd src
python app.py
```

O sistema iniciará em: **http://localhost:5000**

---

## 🎯 Usar o Validador Principal

1. Acesse `http://localhost:5000`
2. Digite a URL alvo (ex: `https://site.com`)
3. Configure opções (opcional):
   - **Scan Duplo**: Testa HTTP e HTTPS
   - **Fuzzing Profundo**: Busca centenas de arquivos sensíveis
   - **SQLi Temporal**: SQL Injection com delay
4. Clique em **INICIAR_SCAN**
5. Aguarde os resultados
6. Baixe o relatório em PDF

---

## 🕵️ Usar o Módulo OSINT

### Acesso

- Clique no botão **🕵️ OSINT** no canto superior direito
- Ou acesse diretamente: `http://localhost:5000/osint`

### Tipos de Investigação

#### 📧 **Investigação de E-mail**
```
1. Selecione o card "Investigação de E-mail"
2. Digite o e-mail: exemplo@dominio.com
3. (Opcional) Marque "Buscar username em redes sociais"
4. Clique em "Iniciar Investigação"
5. Acompanhe o progresso
6. Veja vazamentos, análise de domínio e recomendações
```

**Requer API Key?** Sim, para verificação completa de vazamentos
```bash
# Configurar HaveIBeenPwned API Key
set HIBP_API_KEY=sua-chave-aqui
```
Obtenha em: https://haveibeenpwned.com/API/Key

#### 🌐 **Auditoria de Domínio**
```
1. Selecione "Auditoria de Domínio"
2. Digite o domínio: exemplo.com
3. Configure opções avançadas
4. Veja: WHOIS, DNS, SSL, Geo-IP, Phishing
```

**Não requer API Key** ✅

#### 🎣 **Detecção de Phishing**
```
1. Selecione "Detecção de Phishing"
2. Digite domínio suspeito: dominio-suspeito.com
3. Analise score de risco (0-100)
4. Veja variações de typosquatting detectadas
```

---

## 📊 Exportar Resultados

### OSINT
- **JSON**: Clique em "📊 Exportar JSON"
- **PDF**: Clique em "📄 Baixar PDF" (em desenvolvimento)

### Validador
- **PDF**: Clique em "📄 RELATÓRIO FINAL & DOWNLOAD"
- **Texto**: Use o botão "📋 COPIAR TEXTO" no checklist

---

## 🔧 Configurações Avançadas

### API Keys (Opcional)

```bash
# Windows
set HIBP_API_KEY=sua-chave-hibp
set SHODAN_API_KEY=sua-chave-shodan
set VT_API_KEY=sua-chave-virustotal

# Linux/Mac
export HIBP_API_KEY=sua-chave-hibp
export SHODAN_API_KEY=sua-chave-shodan
export VT_API_KEY=sua-chave-virustotal
```

### Rate Limiting

O sistema possui rate limiting para evitar bloqueios:
- **Validador**: 5 scans por minuto
- **OSINT**: 3 investigações por minuto

---

## 🧪 Testar Módulos

### Teste Rápido dos Módulos
```bash
cd src

# Testar validador de domínio
python -c "from modules.domain_validator import validate_domain; print(validate_domain('google.com'))"

# Testar detector de phishing
python -c "from modules.phishing_detector import detect_phishing; print(detect_phishing('exemplo.com'))"

# Testar motor OSINT
python -m modules.osint_engine
```

---

## ❓ Problemas Comuns

### Erro: "Módulo não encontrado"
```bash
# Certifique-se de estar na pasta src
cd src
pip install -r requirements.txt
```

### Erro: "Porta 5000 em uso"
```python
# Edite app.py, última linha:
app.run(debug=True, port=5001)  # Mude para outra porta
```

### Erro: "API key necessária"
```bash
# Configure a chave antes de iniciar
set HIBP_API_KEY=sua-chave
python app.py
```

### OSINT não carrega CSS
```bash
# Verifique se a pasta static existe
dir static\css
dir static\js

# Deve conter:
# static/css/osint.css
# static/js/osint-controller.js
```

---

## 🎓 Recursos Adicionais

- **Documentação OSINT**: `src/modules/README_OSINT.md`
- **Plano Completo**: `PLANO_IMPLEMENTACAO.md`
- **Código Fonte**: `src/`

---

## 🔒 Segurança

**IMPORTANTE:**
- Este sistema é para **uso local/profissional**
- Não exponha à internet sem configurar:
  - HTTPS com certificado válido
  - Autenticação robusta
  - Firewall e WAF
- Use apenas em alvos autorizados
- Respeite leis e termos de serviço

---

## 📞 Suporte

**Sistema funcionando?**
- ✅ Veja localhost:5000 no navegador
- ✅ Sem erros no console
- ✅ Botão OSINT visível no header

**Problemas?**
- Verifique logs no console
- Teste módulos individualmente
- Reinstale dependências

---

**Validador SEC v2.0 - Pronto para usar! 🚀**

*Desenvolvido com 💚 para profissionais de segurança*
