import phonenumbers
from phonenumbers import geocoder, carrier

val = "+55 11 962229404"
print(f"Testando: {val}")
try:
    parsed = phonenumbers.parse(val, None)
    print(f"Valido: {phonenumbers.is_valid_number(parsed)}")
    print(f"Regiao: {geocoder.description_for_number(parsed, 'pt')}")
    print(f"Operadora: {carrier.name_for_number(parsed, 'pt')}")
except Exception as e:
    print(f"Erro: {e}")
