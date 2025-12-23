import os
import sys
import requests
import zipfile
import shutil
import platform

def install_elite_tools():
    """
    Automated installer for Elite Security Tools (Nuclei, Subfinder, FFuF).
    Downloads binaries from GitHub and sets them up in the project directory.
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    bin_dir = os.path.join(base_dir, "bin", "wins")
    
    if not os.path.exists(bin_dir):
        os.makedirs(bin_dir)
        
    # Standard tools to download (ProjectDiscovery tools + FFuF)
    # We use hardcoded versions for stability, or could use 'latest' logic
    tools = {
        "nuclei": "https://github.com/projectdiscovery/nuclei/releases/download/v3.1.8/nuclei_3.1.8_windows_amd64.zip",
        "subfinder": "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.5/subfinder_2.6.5_windows_amd64.zip",
        "ffuf": "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_windows_amd64.zip"
    }
    
    print("\n" + "="*50)
    print("  INSTALADOR DE ARSENAL ELITE (AUTO)")
    print("="*50)
    
    for name, url in tools.items():
        exe_path = os.path.join(bin_dir, f"{name}.exe")
        
        if os.path.exists(exe_path):
            print(f"[OK] {name.upper()} já está instalado em {exe_path}")
            continue
            
        print(f"[INIT] Baixando {name.upper()}...")
        try:
            zip_path = os.path.join(bin_dir, f"{name}.zip")
            response = requests.get(url, stream=True, timeout=30)
            if response.status_code == 200:
                with open(zip_path, 'wb') as f:
                    shutil.copyfileobj(response.raw, f)
                
                print(f"[INFO] Extraindo {name.upper()}...")
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    # Find the exe inside the zip
                    for file in zip_ref.namelist():
                        if file.endswith('.exe'):
                            zip_ref.extract(file, bin_dir)
                            # If it was in a subfolder or has direct name, we handle it
                            extracted_path = os.path.join(bin_dir, file)
                            target_path = os.path.join(bin_dir, f"{name}.exe")
                            if extracted_path != target_path:
                                if os.path.exists(target_path): os.remove(target_path)
                                os.rename(extracted_path, target_path)
                
                # Cleanup zip
                os.remove(zip_path)
                print(f"[SUCESSO] {name.upper()} instalado com sucesso!")
            else:
                print(f"[ERRO] Falha ao baixar {name.upper()}: Status {response.status_code}")
        except Exception as e:
            print(f"[ERRO] Falha na instalação de {name.upper()}: {str(e)}")

    print("="*50 + "\n")

if __name__ == "__main__":
    if platform.system() == "Windows":
        install_elite_tools()
    else:
        print("Este instalador automático é exclusivo para Windows.")
