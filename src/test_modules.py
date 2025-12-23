# -*- coding: utf-8 -*-
"""Teste rápido dos módulos"""

print("=" * 50)
print("TESTE DOS MODULOS - VALIDADOR SEC")
print("=" * 50)

# 1. Test breach_checker
print("\n1. Testando breach_checker...")
from modules.breach_checker import check_password_breach

result = check_password_breach('password123')
print(f"   Status: {result['status']}")
print(f"   Comprometida: {result['compromised']}")
if result['compromised']:
    print(f"   Vezes vista: {result['times_seen']:,}")

# 2. Test phishing_detector
print("\n2. Testando phishing_detector...")
from modules.phishing_detector import detect_phishing

result = detect_phishing('g00gle.com')
print(f"   Dominio: {result['domain']}")
print(f"   Suspeito: {result['is_suspicious']}")
print(f"   Score de risco: {result['risk_score']}/100")

# 3. Test header_analyzer
print("\n3. Testando header_analyzer...")
from modules.header_analyzer import get_security_score

score = get_security_score('https://google.com')
print(f"   Score de seguranca: {score}/100")

print("\n" + "=" * 50)
print("TODOS OS MODULOS FUNCIONANDO!")
print("=" * 50)
