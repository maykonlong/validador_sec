# 🚀 VALIDADOR SEC v2.0 - COMO INICIAR

## ⚡ INÍCIO RÁPIDO (1 clique)

### Windows:
```
1. Duplo clique em: INICIAR.bat
2. Aguarde a instalação automática de dependências
3. O navegador abrirá automaticamente
```

**Pronto! O sistema está rodando! 🎉**

---

## 🌐 URLs Disponíveis

Após iniciar o sistema:

- **Scanner de Vulnerabilidades**: http://localhost:5000
- **Módulo OSINT**: http://localhost:5000/osint

---

## 🔧 O que o INICIAR.bat faz automaticamente:

1. ✅ Verifica Python instalado
2. ✅ Instala dependências (requirements.txt)
3. ✅ Verifica e libera porta 5000
4. ✅ Inicia servidor Flask
5. ✅ Abre navegador automaticamente

---

## 📦 Módulos Incluídos

Após iniciar, você terá acesso a:

### 🔍 Scanner de Vulnerabilidades
- 120+ testes automáticos
- SQL Injection, XSS, CSRF, etc
- Análise de headers, SSL, DNS
- Relatórios em PDF

### 🕵️ Módulo OSINT
- **📧 Investigação de E-mail** (vazamentos, domínio)
- **🌐 Auditoria de Domínio** (WHOIS, DNS, SSL, Geo-IP)
- **🎣 Detecção de Phishing** (typosquatting, score de risco)
- **👤 Investigação de Pessoa** (em desenvolvimento)
- **📱 Análise de Telefone** (em desenvolvimento)

---

## ❓ Problemas?

### "Python não encontrado"
- Instale Python 3.8+ de: https://www.python.org/downloads/
- Marque "Add Python to PATH" durante instalação

### "Porta 5000 ocupada"
- O INICIAR.bat libera automaticamente
- Ou feche manualmente o processo usando a porta

### "Dependências falharam"
- Execute manualmente:
  ```
  cd src
  pip install -r requirements.txt
  ```

---

## 🔒 Segurança

**Senha padrão do sistema**: `long`

Para alterar, edite no INICIAR.bat:
```batch
REM Gere novo hash SHA-256 e substitua
set VALIDADOR_HASH=seu-novo-hash-aqui
```

---

## 📚 Documentação Completa

- **Guia Rápido**: INICIO_RAPIDO.md
- **Resumo Executivo**: RESUMO_EXECUTIVO.md
- **Plano Completo**: PLANO_IMPLEMENTACAO.md
- **Doc OSINT**: src/modules/README_OSINT.md

---

## 🎯 Uso Básico

### Scanner (URL Principal)
1. Digite URL alvo: `https://site.com`
2. Configure opções (duplo scan, fuzzing)
3. Clique "INICIAR_SCAN"
4. Veja resultados em tempo real
5. Baixe relatório PDF

### OSINT (Botão 🕵️ OSINT)
1. Escolha tipo de investigação
2. Preencha dados do alvo
3. Configure opções avançadas
4. Clique "Iniciar Investigação"
5. Acompanhe progresso
6. Exporte JSON/PDF

---

## 💚 Pronto para Usar!

Simplesmente execute:
```
INICIAR.bat
```

**E comece a usar o Validador SEC v2.0! 🚀**

---

*Desenvolvido com 💚 para profissionais de segurança*
