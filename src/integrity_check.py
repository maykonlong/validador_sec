import hashlib
import json
import base64
import os
import sys

def xor_decode(data, key=0x7F):
    """Decodifica dados ofuscados com XOR"""
    return ''.join(chr(ord(c) ^ key) for c in data)

def calculate_file_hash(filepath):
    """Calcula SHA-256 de um arquivo"""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except:
        return None

def verify_integrity():
    """
    Verifica integridade dos arquivos críticos.
    Retorna: (is_valid, error_message)
    """
    
    integrity_file = os.path.join(os.path.dirname(__file__), '.integrity')
    
    if not os.path.exists(integrity_file):
        return (False, "Arquivo de integridade não encontrado!")
    
    try:
        # Lê e decodifica arquivo
        with open(integrity_file, 'r') as f:
            encoded_content = f.read()
        
        # Decodifica Base64
        json_str = base64.b64decode(encoded_content).decode()
        integrity_data = json.loads(json_str)
        
        # Valida assinatura do arquivo .integrity
        signature = integrity_data.pop('s')
        signature_hash = xor_decode(signature)
        
        calculated_sig = hashlib.sha256(json.dumps(integrity_data, sort_keys=True).encode()).hexdigest()
        
        if calculated_sig != signature_hash:
            return (False, "Arquivo .integrity foi adulterado!")
        
        # Reinsere assinatura
        integrity_data['s'] = signature
        
        # Verifica cada arquivo protegido
        base_dir = os.path.dirname(os.path.abspath(__file__))
        
        for encoded_name, encoded_hash in integrity_data['d'].items():
            # Decodifica nome (ex: app.py, templates/index.html)
            rel_path = base64.b64decode(encoded_name).decode()
            filepath = os.path.join(base_dir, rel_path)
            
            # Decodifica hash esperado
            expected_hash = xor_decode(encoded_hash)
            
            # Calcula hash atual
            current_hash = calculate_file_hash(filepath)
            
            if current_hash is None:
                return (False, "Arquivo critico ausente ou inacessivel")
            
            if current_hash != expected_hash:
                return (False, "Integridade violada - adulteracao detectada")
        
        return (True, None)
        
    except Exception as e:
        return (False, f"Erro ao validar integridade: {str(e)}")

def block_execution_alert():
    """Exibe alerta visual de sistema comprometido"""
    import webbrowser
    import os
    
    # Caminho para página de alerta
    alert_page = os.path.join(os.path.dirname(__file__), 'templates', 'compromised.html')
    
    # Abre no navegador
    if os.path.exists(alert_page):
        webbrowser.open('file://' + os.path.abspath(alert_page))
    
    # Também mostra no console (sem detalhes do arquivo)
    print("\n" + "="*60)
    print("🚨 ALERTA DE SEGURANÇA - SISTEMA COMPROMETIDO 🚨".center(60))
    print("="*60)
    print("\n⚠️  Detectada adulteração nos arquivos do sistema!")
    print("\n📋 INSTRUÇÕES:")
    print("  1. NÃO execute este software")
    print("  2. Restaure da fonte original confiável")
    print("  3. Execute integrity_generate.py novamente")
    print("\n" + "="*60 + "\n")

if __name__ == '__main__':
    # Teste standalone
    is_valid, error = verify_integrity()
    
    if not is_valid:
        block_execution_alert()
        print(f"[ERRO] {error}\n")
        sys.exit(1)
    else:
        print("\n✅ Integridade verificada com sucesso!")
        print("   Todos os arquivos críticos estão íntegros.\n")
