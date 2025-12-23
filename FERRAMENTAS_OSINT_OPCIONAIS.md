# 🔧 Ferramentas OSINT Opcionais - Guia de Instalação

## 📊 Visão Geral

O Validador SEC v2.0 agora suporta integração automática com ferramentas OSINT populares:
- **Sherlock** - Busca de usernames em 300+ sites
- **Maigret** - Extensão do Sherlock com mais sites e funcionalidades

Essas ferramentas são **opcionais** mas muito recomendadas para investigações completas!

---

## 🚀 Como Funciona

### Detecção Automática:
1. O sistema verifica se Sherlock/Maigret estão instalados
2. Se disponíveis, executa automaticamente durante investigação de pessoa
3. Se não disponíveis, faz busca manual básica (8 redes sociais)

### Vantagens com Ferramentas Instaladas:
- ✅ **300+ sites** verificados (vs 8 manual)
- ✅ **Resultados mais precisos** (validação real)
- ✅ **Dados estruturados** (JSON completo)
- ✅ **Mais rápido** (paralelização)

---

## 📦 Instalação

### Opção 1: Sherlock (Recomendado para Iniciantes)

#### Windows:
```bash
pip install sherlock-project
```

#### Linux/Mac:
```bash
pip3 install sherlock-project
```

#### Verificar Instalação:
```bash
sherlock --version
```

### Opção 2: Maigret (Mais Avançado)

#### Windows/Linux/Mac:
```bash
pip install maigret
```

#### Verificar Instalação:
```bash
maigret --version
```

### Opção 3: Ambos (Recomendado!)
```bash
pip install sherlock-project maigret
```

---

## 🧪 Testar Integração

### 1. Via OSINT Module:
```
1. Acesse http://localhost:5000/osint
2. Selecione "Investigação de Pessoa"
3. Digite um username (ex: "torvalds")
4. Inicie investigação
5. Veja resultados de Sherlock/Maigret (se instalados)
```

### 2. Via Python:
```python
from modules.osint_engine import execute_osint_mission

result = execute_osint_mission(
    'person',
    'torvalds',
    {}
)

print("Sherlock disponível:", result['summary']['sherlock_available'])
print("Maigret disponível:", result['summary']['maigret_available'])
print("Perfis encontrados:", result['summary']['total_profiles_found'])
```

---

## 📊 Comparação: Com vs Sem Ferramentas

### Sem Sherlock/Maigret (Busca Manual):
```
👤 Investigação de Pessoa
━━━━━━━━━━━━━━━━━━━━━━━━
Username: exemplo123

✅ Busca Manual em Redes Sociais
   8 perfil(is) possivelmente encontrado(s)
   - GitHub
   - Twitter
   - Instagram
   - LinkedIn
   - Facebook
   - Reddit
   - YouTube
   - TikTok

💡 Recomendação:
   Para investigação mais completa, instale:
   pip install sherlock-project
```

### Com Sherlock/Maigret:
```
👤 Investigação de Pessoa
━━━━━━━━━━━━━━━━━━━━━━━━
Username: exemplo123

🔍 Sherlock - Busca Avançada
   ✅ 45 perfil(is) encontrado(s) em 300+ sites
   
   Perfis confirmados:
   • GitHub: github.com/exemplo123
   • Twitter: twitter.com/exemplo123
   • Reddit: reddit.com/user/exemplo123
   • Steam: steamcommunity.com/id/exemplo123
   • Pinterest: pinterest.com/exemplo123
   • ... +40 sites

🔍 Maigret - Busca Profunda
   ✅ 52 perfil(is) encontrado(s)
   
   Sites adicionais:
   • Habr
   • VK
   • Telegram
   • ... +mais sites internacionais
```

---

## ⚙️ Configuração Avançada

### Timeout Customizado:

O sistema usa timeouts conservadores por padrão:
- **Sherlock**: 60 segundos
- **Maigret**: 90 segundos

Para investigações mais profundas, você pode editar:

`src/modules/osint_engine.py`:
```python
# Linha ~500
timeout=60  # Aumente para 120+ se necessário

# Linha ~560
timeout=90  # Aumente para 180+ se necessário
```

---

## 🔍 Sites Verificados

### Sherlock (300+ sites):
- Redes Sociais: Twitter, Instagram, Facebook, etc
- Dev: GitHub, GitLab, StackOverflow
- Fóruns: Reddit, HackerNews, Quora
- Gaming: Steam, Twitch, Xbox Live
- Outros: Pinterest, Medium, Imgur, etc

### Maigret (400+ sites):
- Todos do Sherlock +
- Sites russos: VK, Habr, Yandex
- Sites internacionais
- Fóruns especializados
- Plataformas menos conhecidas

---

## 🐛 Solução de Problemas

### "Sherlock não encontrado"
```bash
# Windows
where sherlock
# Se não aparecer nada, instale:
pip install --upgrade sherlock-project

# Linux/Mac
which sherlock
# Se não aparecer nada:
pip3 install --upgrade sherlock-project
```

### "Maigret não encontrado"
```bash
# Mesma lógica:
pip install --upgrade maigret
```

### Timeout muito longo
- Reduza timeout nos arquivos de configuração
- Use apenas Sherlock (mais rápido)
- Desabilite busca profunda

### Resultados vazios
- Username pode não existir em redes sociais
- Alguns sites podem estar bloqueando
- Tente com username conhecido (ex: "torvalds")

---

## 📝 Requisitos

### Sistema:
- Python 3.8+
- pip instalado
- Conexão com internet

### Dependências Automáticas:
Sherlock e Maigret instalam suas próprias dependências:
- requests
- beautifulsoup4
- torrequest (Maigret)
- etc

---

## 💡 Dicas de Uso

### 1. Username Conhecidos para Teste:
- `torvalds` (Linus Torvalds - Linux)
- `gvanrossum` (Guido van Rossum - Python)
- `github` (Conta oficial GitHub)

### 2. Melhores Práticas:
- Use Sherlock para busca rápida
- Use Maigret para investigação profunda
- Sempre verifique manualmente os perfis
- Respeite privacidade e leis locais

### 3. Performance:
- Sherlock é mais rápido (~1 min)
- Maigret é mais completo (~2-3 min)
- Execute ambos para máxima cobertura

---

## 📊 Exemplo de Resultado Completo

```json
{
  "summary": {
    "username": "torvalds",
    "sherlock_available": true,
    "maigret_available": true,
    "total_profiles_found": 87,
    "status": "completed"
  },
  "findings": [
    {
      "type": "sherlock_scan",
      "title": "🔍 Sherlock - Busca Avançada",
      "description": "✅ Sherlock encontrou 45 perfil(is)",
      "data": {
        "profiles": [
          {"site": "GitHub", "url": "https://github.com/torvalds"},
          {"site": "Twitter", "url": "https://twitter.com/torvalds"},
          ...
        ]
      }
    },
    {
      "type": "maigret_scan",
      "title": "🔍 Maigret - Busca Profunda",
      "description": "✅ Maigret encontrou 42 perfil(is)",
      "data": {...}
    }
  ]
}
```

---

## 🎯 Status e Roadmap

### Implementado:
- ✅ Detecção automática de Sherlock
- ✅ Detecção automática de Maigret
- ✅ Fallback para busca manual
- ✅ Parse de resultados JSON
- ✅ Limpeza de arquivos temporários
- ✅ Timeout de segurança

### Futuro:
- [ ] Cache de resultados
- [ ] Busca incremental
- [ ] Filtros por tipo de site
- [ ] Exportação de grafos de relações

---

## 📞 Suporte

**Problemas com Sherlock/Maigret:**
- Visite: https://github.com/sherlock-project/sherlock
- Visite: https://github.com/soxoj/maigret

**Problemas com Integração:**
- Verifique logs do sistema
- Teste ferramentas individualmente
- Reporte no repositório do Validador SEC

---

**Validador SEC v2.0 - Agora com Sherlock & Maigret! 🕵️🔍**

*Última atualização: 21/12/2025*
