import sys
import subprocess
import os

print("=== DIAGNOSTICO OSINT ===")
print(f"Python: {sys.executable}")
print(f"CWD: {os.getcwd()}")

def test_cmd(name, cmd_list):
    print(f"\n--- Testando {name} ---")
    print(f"Comando: {cmd_list}")
    try:
        # Tenta rodar versão rapida (help ou version)
        res = subprocess.run(cmd_list, capture_output=True, text=True, timeout=10)
        print(f"Return Code: {res.returncode}")
        if res.stdout: print(f"STDOUT (inicio): {res.stdout[:200]}...")
        if res.stderr: print(f"STDERR (inicio): {res.stderr[:200]}...")
        return res.returncode == 0
    except FileNotFoundError:
        print("ERRO: Comando nao encontrado (FileNotFound)")
        return False
    except Exception as e:
        print(f"ERRO: {e}")
        return False

# 1. Testar Sherlock (comando direto)
test_cmd("Sherlock (CMD)", ["sherlock", "--version"])

# 2. Testar Sherlock (modulo python)
test_cmd("Sherlock (Module)", [sys.executable, "-m", "sherlock_project", "--version"])

# 3. Testar Maigret (comando direto)
test_cmd("Maigret (CMD)", ["maigret", "--version"])

# 4. Testar Maigret (modulo python)
test_cmd("Maigret (Module)", [sys.executable, "-m", "maigret", "--version"])

print("\n=== FIM DO DIAGNOSTICO ===")
