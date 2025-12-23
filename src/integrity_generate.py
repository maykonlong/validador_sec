import hashlib
import json
import base64
import os

def xor_encode(data, key=0x7F):
    """Ofusca dados com XOR simples"""
    return ''.join(chr(ord(c) ^ key) for c in data)

def calculate_file_hash(filepath):
    """Calcula SHA-256 de um arquivo"""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def generate_integrity_file():
    """Gera arquivo de integridade com hashes ofuscados"""
    
    # Base dir = diretório onde o script está (src/)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Arquivos críticos (relativos ao base_dir)
    files_to_protect = [
        os.path.join(base_dir, 'app.py'),
        os.path.join(base_dir, 'scanner.py'), 
        os.path.join(base_dir, 'reporter.py'),
        os.path.join(base_dir, 'templates', 'index.html')
    ]
    
    integrity_data = {
        'v': 1,  # versão
        'd': {}  # dados
    }
    
    print("[GERADOR] Calculando hashes dos arquivos críticos...")
    
    for filepath in files_to_protect:
        if os.path.exists(filepath):
            file_hash = calculate_file_hash(filepath)
            
            # Ofusca caminho absoluto para relativo (base64)
            # Para manter consistência com o check, salva apenas o path relativo se possível,
            # ou ajusta o check. O check verifica calculate_file_hash(filepath).
            # O check lê do keys do json.
            # Vamos salvar o path relativo no JSON para portabilidade
            rel_path = os.path.relpath(filepath, base_dir)
            # Normalizar para forward slashes para evitar problemas com OS
            rel_path = rel_path.replace('\\', '/')
            
            encoded_name = base64.b64encode(rel_path.encode()).decode()
            
            # Ofusca hash (XOR)
            encoded_hash = xor_encode(file_hash)
            
            integrity_data['d'][encoded_name] = encoded_hash
            print(f"  [OK] {rel_path}")
        else:
            print(f"  [X] {filepath} (nao encontrado)")
    
    # Calcula hash da própria assinatura (sem o campo 's')
    signature_content = json.dumps(integrity_data, sort_keys=True)
    signature_hash = hashlib.sha256(signature_content.encode()).hexdigest()
    integrity_data['s'] = xor_encode(signature_hash)
    
    # Salva arquivo ofuscado no mesmo diretório
    output_file = os.path.join(base_dir, '.integrity')
    
    # Adiciona mais uma camada: base64 do JSON inteiro
    json_str = json.dumps(integrity_data, separators=(',', ':'))
    encoded_content = base64.b64encode(json_str.encode()).decode()
    
    with open(output_file, 'w') as f:
        f.write(encoded_content)
    
    print(f"\n[OK] Arquivo de integridade gerado: {output_file}")
    print(f"[INFO] {len(integrity_data['d'])} arquivos protegidos")
    print("\n[ATENÇÃO] Mantenha este arquivo privado!")

if __name__ == '__main__':
    generate_integrity_file()
