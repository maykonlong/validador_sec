# -*- coding: utf-8 -*-
"""Teste do scanner com módulos integrados"""

from scanner import VulnerabilityScanner

print("=" * 60)
print("TESTE DO SCANNER COM MÓDULOS INTEGRADOS")
print("=" * 60)

# Criar scanner com URL de teste
test_url = "https://google.com"
print(f"\nTestando scanner em: {test_url}\n")

def progress_callback(msg):
    print(f"  → {msg}")

# Criar instância do scanner
scanner = VulnerabilityScanner(test_url, progress_callback=progress_callback)

# Executar apenas os novos módulos para teste rápido
print("\n[1/4] Testando Validação de Domínio...")
scanner.check_domain_validation()

print("\n[2/4] Testando Verificação de Vazamentos...")
scanner.check_data_breaches()

print("\n[3/4] Testando Detecção de Phishing...")
scanner.check_phishing_indicators()

print("\n[4/4] Testando Análise de Headers Avançados...")
scanner.check_advanced_headers()

# Mostrar resultados
print("\n" + "=" * 60)
print(f"RESULTADOS: {len(scanner.results)} verificações executadas")
print("=" * 60)

for i, result in enumerate(scanner.results[:10], 1):  # Mostrar apenas primeiros 10
    status_symbol = {
        'Safe': '✅',
        'Info': 'ℹ️',
        'Warning': '⚠️',
        'Vulnerable': '❌',
        'Error': '⛔'
    }.get(result['status'], '•')
    
    print(f"\n{i}. {status_symbol} {result['vulnerability']}")
    print(f"   Status: {result['status']} | Severidade: {result['severity']}")
    print(f"   Categoria: {result['category']}")

if len(scanner.results) > 10:
    print(f"\n... e mais {len(scanner.results) - 10} resultados")

print("\n" + "=" * 60)
print("TESTE CONCLUÍDO COM SUCESSO!")
print("=" * 60)
