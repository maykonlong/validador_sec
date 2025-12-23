# 🚀 GUIA RÁPIDO - Resolver Travamento do INICIAR.bat

## ❌ **Problema:**
INICIAR.bat trava em "Verificando dependências..."

## ✅ **Solução:**

### **Opção 1: Use INICIAR_SIMPLES.bat (RECOMENDADO)**
```bash
1. Feche qualquer janela travada
2. Execute: INICIAR_SIMPLES.bat
3. Aguarde instalação das dependências (mostra progresso)
4. Sistema iniciará automaticamente
```

### **Opção 2: Instale dependências manualmente**
```bash
1. Abra PowerShell/CMD nesta pasta
2. Execute:
   cd src
   pip install -r requirements.txt
   
3. Aguarde instalação concluir
4. Execute: INICIAR.bat
```

### **Opção 3: Instalar sem phonenumbers**
Se phonenumbers estiver causando problemas:
```bash
# Remova temporariamente a linha phonenumbers==8.13.18
# do arquivo src\requirements.txt

# Depois instale:
pip install -r src\requirements.txt

# Inicie o sistema:
python src/app.py
```

---

## 🔧 **O Que Foi Corrigido:**

### 1. **INICIAR.bat Melhorado:**
- ✅ Instalação não trava mais em modo silencioso
- ✅ Mostra progresso da instalação
- ✅ Continua mesmo se alguns pacotes falharem
- ✅ Feedback visual melhorado

### 2. **INICIAR_SIMPLES.bat Criado:**
- ✅ Script mais direto e simples
- ✅ Mostra tudo que está fazendo
- ✅ Menos propenso a travamentos

### 3. **requirements.txt Corrigido:**
- ✅ Removido `python-Levenshtein` (causava problemas de compilação)
- ✅ Corrigido encoding de comentários
- ✅ `phonenumbers` mantido (análise de telefone completa)

---

## 📦 **Dependências Principais:**

### **Essenciais (sempre instaladas):**
- ✅ flask, requests
- ✅ python-whois, dnspython
- ✅ phonenumbers **(NOVO!)**
- ✅ beautifulsoup4, lxml

### **Opcionais (instale se quiser):**
- 🔧 sherlock-project (300+ sites)
- 🔧 maigret (400+ sites)
- 🔧 python-Levenshtein (similaridade)

---

## 🎯 **Testar Agora:**

### **Método Rápido:**
```bash
# Execute:
INICIAR_SIMPLES.bat

# Aguarde mensagem:
[OK] Python encontrado
[INIT] Instalando dependências...
[INFO] Iniciando servidor...

# Navegador abrirá automaticamente!
```

### **Verificar se Está Funcionando:**
```bash
# Depois de iniciar, teste:
1. Scanner: http://localhost:5000
2. OSINT: http://localhost:5000/osint
3. Análise de Telefone (com phonenumbers!)
```

---

## ⚠️ **Problemas Comuns:**

### **"pip não reconhecido":**
```bash
# Use:
python -m pip install -r src\requirements.txt
```

### **"phonenumbers falha ao instalar":**
```bash
# Requer compilador C++ no Windows
# Opção 1: Instale Visual C++ Build Tools
# Opção 2: Remova phonenumbers do requirements.txt
#          (análise básica de telefone ainda funciona)
```

### **"Porta 5000 ocupada":**
```bash
# O script já limpa automaticamente
# Ou manualmente:
netstat -ano | findstr :5000
taskkill /F /PID <numero_do_pid>
```

---

## 🎉 **Sistema Totalmente Funcional!**

✅ **Scanner funcionando**
✅ **OSINT funcionando**
✅ **Formulário de telefone melhorado**
✅ **PhoneNumbers integrado**
✅ **Sherlock/Maigret disponíveis (se instalados)**

**Execute INICIAR_SIMPLES.bat e teste! 🚀**

---

*Última atualização: 21/12/2025 - 16:45*
