# 🕵️ Módulo OSINT - Validador SEC

## Visão Geral

O módulo OSINT (Open Source Intelligence) é uma extensão do Validador SEC que oferece investigações avançadas e modulares para análise de segurança.

## ✨ Funcionalidades

### 5 Tipos de Investigação

1. **📧 Investigação de E-mail**
   - Verificação em vazamentos públicos (HaveIBeenPwned)
   - Análise do domínio associado
   - Busca de username em redes sociais (em desenvolvimento)

2. **🌐 Auditoria de Domínio**
   - Informações WHOIS
   - Registros DNS (A, MX, TXT, etc)
   - Análise SSL/TLS completa
   - Geolocalização do servidor
   - Detecção de indicadores de phishing

3. **🎣 Detecção de Phishing**
   - Análise de typosquatting
   - Verificação de palavras suspeitas
   - Detecção de ataques homográficos
   - Geração de variações maliciosas

4. **👤 Investigação de Pessoa** (em desenvolvimento)
   - Busca em redes sociais
   - Correlação de dados públicos
   - Grafos de relacionamentos

5. **📱 Análise de Telefone** (em desenvolvimento)
   - Validação de formato
   - Identificação de operadora
   - Detecção em vazamentos

## 🚀 Como Usar

### Interface Web

1. Acesse `/osint` no navegador
2. Selecione o tipo de investigação
3. Preencha os dados do alvo
4. Configure opções avançadas (opcional)
5. Clique em "Iniciar Investigação"
6. Acompanhe o progresso em tempo real
7. Baixe o relatório em PDF ou JSON

### API Python

```python
from modules.osint_engine import execute_osint_mission

# Investigação de e-mail
result = execute_osint_mission(
    mission_type='email',
    target='test@example.com',
    options={'search_username': False}
)

print(result['summary'])
print(result['findings'])
```

### Exemplo Completo

```python
from modules.osint_engine import OsintEngine

# Criar engine
engine = OsintEngine(
    mission_type='domain',
    target='google.com',
    options={
        'subdomain_enum': False,
        'ssl_deep': True
    }
)

# Callback de progresso
def on_progress(percent, message):
    print(f"[{percent}%] {message}")

engine.set_progress_callback(on_progress)

# Executar investigação
results = engine.execute_mission()

# Acessar resultados
print("Status:", results['metadata']['status'])
print("Findings:", len(results['findings']))

for finding in results['findings']:
    print(f"\n- {finding['title']}")
    print(f"  Severidade: {finding['severity']}")
    print(f"  {finding['description']}")
```

## 🔑 Configuração de API Keys

Algumas funcionalidades requerem API keys:

### HaveIBeenPwned (Verificação de E-mail)

```bash
# Windows
set HIBP_API_KEY=sua-chave-aqui

# Linux/Mac
export HIBP_API_KEY=sua-chave-aqui
```

Obtenha sua chave em: https://haveibeenpwned.com/API/Key

## 📊 Estrutura de Resultados

```json
{
  "findings": [
    {
      "type": "data_breach",
      "severity": "high",
      "title": "E-mail encontrado em vazamentos",
      "description": "5 vazamento(s) detectado(s)",
      "data": { ... }
    }
  ],
  "summary": {
    "total_findings": 5,
    "total_breaches": 5,
    "risk_level": "high"
  },
  "recommendations": [
    "Trocar senha imediatamente",
    "Habilitar 2FA"
  ],
  "metadata": {
    "mission_type": "email",
    "target": "test@example.com",
    "start_time": "2025-12-21T16:00:00",
    "duration_seconds": 12.5,
    "status": "completed"
  }
}
```

## 🔒 Segurança

- **Rate Limiting**: 3 investigações por minuto
- **CSRF Protection**: Tokens validados em todas as requisições
- **Input Sanitization**: Validação rigorosa de entradas
- **Session Management**: Resultados isolados por sessão

## 🧪 Testes

### Testar Módulos Individuais

```bash
# Testar motor OSINT
python -m modules.osint_engine

# Testar validação de domínio
python -m modules.domain_validator

# Testar detector de phishing
python -m modules.phishing_detector
```

### Testar Interface

```bash
# Iniciar servidor
python app.py

# Acessar no navegador
http://localhost:5000/osint
```

## 📚 Módulos Incluídos

### `osint_engine.py`
Motor principal de investigações OSINT

### `domain_validator.py`
- Validação de domínios
- WHOIS, DNS, SSL, Geo-IP

### `breach_checker.py`
- Verificação de e-mails em vazamentos
- Verificação de senhas comprometidas (k-anonymity)
- Cache e rate limiting

### `phishing_detector.py`
- Detecção de typosquatting
- Análise de indicadores suspeitos
- Geração de variações maliciosas

### `header_analyzer.py`
- Análise de headers HTTP
- Score de segurança
- Detecção de tecnologias

## 🎨 Interface

- **Design Cyber Security**: Tema escuro com neon
- **Formulários Dinâmicos**: Campos mudam conforme missão
- **Progress Streaming**: Updates em tempo real
- **Resultados Interativos**: Cards expansíveis com detalhes

## 🔮 Roadmap

### Em Desenvolvimento
- [ ] Integração Sherlock/Maigret (busca em redes sociais)
- [ ] Enumeração de subdomínios
- [ ] Análise de telefone (phonenumbers)
- [ ] Geração de PDF customizado
- [ ] Busca em Wayback Machine
- [ ] Screenshot de domínios

### Futuro
- [ ] Busca em darkweb (Tor integration)
- [ ] Análise de blockchain
- [ ] Correlação com threat intelligence
- [ ] Export para formatos STIX/TAXII

## 📞 Suporte

Para reportar bugs ou sugerir melhorias, abra uma issue no repositório.

---

**Validador SEC - OSINT Module v2.0**  
*Desenvolvido com 💚 para a comunidade de segurança*
