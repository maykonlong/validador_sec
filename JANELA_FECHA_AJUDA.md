# ⚠️ JANELA FECHA AUTOMATICAMENTE? LEIA AQUI!

## 🔴 **Problema: Tela pisca e some**

Se ao clicar em qualquer `.bat` a janela abre e fecha rapidamente, siga os passos abaixo:

---

## ✅ **SOLUÇÃO RÁPIDA:**

### **1️⃣ Use o Script de Debug:**

```
1. Clique com botão DIREITO em: INICIAR_DEBUG.bat
2. Selecione: "Executar como administrador"
3. A janela VAI FICAR ABERTA e mostrar o erro
```

Este script:
- ✅ Mostra todos os passos
- ✅ Identifica o problema exato
- ✅ NÃO fecha automaticamente
- ✅ Aguarda você pressionar uma tecla

---

### **2️⃣ Problemas Comuns:**

#### **A) Python não instalado ou não está no PATH:**

**Sintomas:**
- Janela fecha imediatamente
- Nada acontece

**Solução:**
```
1. Baixe Python: https://www.python.org/downloads/
2. Durante instalação:
   ☑️ MARQUE: "Add Python to PATH"  ← IMPORTANTE!
3. Instale normalmente
4. Execute INICIAR_DEBUG.bat novamente
```

**Verificar se Python está OK:**
```cmd
# Abra CMD e digite:
python --version

# Deve mostrar algo como:
Python 3.11.0
```

---

#### **B) Script executado da pasta errada:**

**Sintomas:**
- Erro: "src não encontrado"
- Erro: "app.py não encontrado"

**Solução:**
```
1. Certifique-se de estar na pasta:
   validador_sec-main\

2. Estrutura deve ser:
   validador_sec-main\
   ├── INICIAR.bat
   ├── INICIAR_DEBUG.bat
   ├── src\
   │   ├── app.py
   │   ├── requirements.txt
   │   └── ...

3. Execute o .bat da pasta raiz
```

---

#### **C) Falta de permissões:**

**Sintomas:**
- Erro ao instalar pacotes
- "Access denied"

**Solução:**
```
1. Clique com BOTÃO DIREITO no .bat
2. "Executar como administrador"
3. Aceite o UAC (controle de conta)
```

---

## 📋 **VERIFICAÇÃO MANUAL:**

Se INICIAR_DEBUG.bat também fechar, faça isto:

### **1. Abra PowerShell/CMD manualmente:**
```
Windows + R
Digite: cmd
Enter
```

### **2. Navegue até a pasta:**
```cmd
cd C:\Users\Acer\Projetos\validador_sec-main
```

### **3. Teste Python:**
```cmd
python --version
```

**Se der erro:** Python não está instalado ou no PATH

**Se funcionar:** Vá para próximo passo

### **4. Teste instalação:**
```cmd
cd src
pip install -r requirements.txt
```

**Se der erro:** Anote o erro e procure solução específica

**Se funcionar:** Python está OK!

### **5. Teste inicialização:**
```cmd
python app.py
```

**Se funcionar:** Sistema iniciará!
**Acesse:** http://localhost:5000

---

## 🎯 **ORDEM DE EXECUÇÃO:**

### **Primeira tentativa:**
```
INICIAR_DEBUG.bat
```
→ Mostrará exatamente o que está errado

### **Se Python não está instalado:**
```
1. Instale Python (com PATH!)
2. Execute INICIAR_DEBUG.bat novamente
```

### **Se Python está OK mas dependências falham:**
```
1. Abra CMD como administrador
2. cd validador_sec-main\src
3. pip install -r requirements.txt
4. Execute INICIAR_DEBUG.bat
```

### **Se tudo falhar:**
```
# Modo manual:
1. Abra CMD
2. cd validador_sec-main
3. python src/app.py
4. Abra navegador: http://localhost:5000
```

---

## 🆘 **AINDA NÃO FUNCIONA?**

Cole a saída do INICIAR_DEBUG.bat aqui e eu ajudo!

Ou teste manualmente e copie a mensagem de erro:
```cmd
cd C:\Users\Acer\Projetos\validador_sec-main
python src/app.py
```

---

## ✅ **CHECKLIST FINAL:**

Antes de executar qualquer .bat, verifique:

- [ ] Python instalado (python --version funciona)
- [ ] Python no PATH (variável de ambiente)
- [ ] Na pasta correta (validador_sec-main\)
- [ ] Pasta src\ existe
- [ ] Arquivo src\app.py existe
- [ ] Executando como administrador (se necessário)

---

**Execute INICIAR_DEBUG.bat e veja o erro específico! 🔍**

*Última atualização: 21/12/2025 - 16:47*
