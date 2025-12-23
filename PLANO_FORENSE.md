# 🕵️ PLANO MÓDULO 3: LABORATÓRIO FORENSE (CYBER LAB)

**Objetivo:** Adicionar capacidade de análise de arquivos e artefatos digitais ao Validador SEC, transformando-o em uma suíte completa de investigação.

---

## 🏗️ 1. Funcionalidades (MVP)

### A. 📸 Extrator de Metadados (MetadataX)
*   **O que faz:** O usuário envia uma foto (`.jpg`, `.jpeg`, `.png`). O sistema extrai dados ocultos.
*   **O que revela:**
    *   📍 **Geolocalização:** Mapa exato de onde a foto foi tirada (se houver GPS).
    *   📱 **Dispositivo:** Modelo do celular/câmera (ex: "iPhone 13").
    *   📅 **Timeline:** Data original da criação x Data de modificação.
    *   🛠️ **Edição:** Mostra se passou por Photoshop/Canva.

### B. 🦠 Scanner de Integridade (HashCheck)
*   **O que faz:** O usuário envia qualquer arquivo suspeito (PDF, EXE, DOCX).
*   **O que revela:**
    *   🔐 **Cálculo de Hash:** Gera MD5, SHA-1 e SHA-256 (a "digital" do arquivo).
    *   🌍 **Intel Check:** Cria links diretos para verificar esse hash no **VirusTotal**, **Hybrid Analysis** e **Talos** (sem precisar de API Key paga).
    *   🛡️ **Segurança:** O arquivo é analisado na memória e descartado, garantindo segurança.

### C. 🧹 O "Limpador" (Scrubber)
*   **O que faz:** Remove metadados sensíveis para proteger a privacidade.
*   **Uso:** "Quero postar essa foto da minha casa, mas não quero que saibam meu endereço (GPS)."
*   **Como:** O sistema reprocessa a imagem/PDF, stripando tags EXIF e XMP, e devolve uma cópia limpa.

---

## 🛠️ 2. Arquitetura Técnica

### Backend (Python/Flask)
Não precisamos de softwares externos complexos. Usaremos bibliotecas Python puras:
*   `Pillow (PIL)`: Para manipulação de imagens e extração EXIF.
*   `PyPDF2` ou `pikepdf`: Para análise e limpeza de PDFs.
*   `hashlib`: Nativa do Python para criptografia.

### Frontend
*   **Nova Aba:** "Laboratório Forense" no menu principal.
*   **Drag & Drop:** Área de upload moderna e arrastável.
*   **Mapa Interativo:** Leaflet.js (o mesmo que já usamos, se tiver) ou link para Google Maps.

---

## 📅 3. Cronograma de Implementação (Estimativa: 1-2 Horas)

### **Fase 1: Configuração (10 min)**
1.  Criar rotas no Flask (`/forensics`).
2.  Criar template HTML base (`forensics.html`).
3.  Instalar bibliotecas (`Pillow`).

### **Fase 2: Motor de Imagens (30 min)**
1.  Implementar `ImageAnalyzer`: Classe para ler EXIF.
2.  Criar função de conversão de coordenadas GPS (DMS -> Decimal).
3.  Testar com fotos reais de smartphone.

### **Fase 3: Motor de Arquivos & Hash (20 min)**
1.  Implementar `FileHasher`: Leitura de buffer e cálculo de hash.
2.  Gerar links dinâmicos para VirusTotal.

### **Fase 4: O Limpador (20 min)**
1.  Criar rota de download e processamento.
2.  Salvar imagem sem metadados em buffer de memória.

### **Fase 5: Integração (10 min)**
1.  Adicionar ao Menu Principal.
2.  Testes finais.

---

## 🚀 4. Como Começar?

Se aprovado, o **Passo 1** é instalar a biblioteca de imagens e preparar a estrutura de pastas.

```bash
pip install Pillow
```

**Deseja iniciar a execução deste plano agora?**
