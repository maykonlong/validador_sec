import os
import zipfile
import pypdf
import io
# Tenta importar OpenSSL, se falhar, desabilita PCKS12
try:
    from OpenSSL import crypto
    HAS_OPENSSL = True
except ImportError:
    HAS_OPENSSL = False

from .hash_cracker import HashCracker

class FileCracker:
    """Quebra senhas de arquivos (PFX, PDF, ZIP) usando força bruta"""
    
    def __init__(self):
        self.cracker = HashCracker()
        
    def crack_file(self, file_path, file_bytes):
        """Identifica tipo e tenta quebrar"""
        ext = os.path.splitext(file_path)[1].lower()
        
        if ext in ['.p12', '.pfx']:
            if not HAS_OPENSSL:
                return {'status': 'error', 'message': 'Módulo pyOpenSSL não instalado.'}
            return self._crack_pkcs12(file_bytes)
            
        elif ext == '.pdf':
            return self._crack_pdf(file_bytes)
            
        elif ext == '.zip':
            # Zipfile precisa de path ou file-like seekable
            if os.path.exists(file_path):
                return self._crack_zip(file_path)
            else:
                 # Try memory
                 return self._crack_zip_memory(file_bytes)
                 
        elif ext in ['.pem', '.key', '.crt', '.cer']:
             # .cer as vezes é usado para chave privada erroneamente ou contém chain
             if not HAS_OPENSSL:
                return {'status': 'error', 'message': 'Módulo pyOpenSSL não instalado.'}
             return self._crack_pem(file_bytes)

        else:
            return {'status': 'error', 'message': f'Extensão {ext} não suportada. Use: PFX, P12, PDF, ZIP, PEM, KEY'}
            
    def _crack_pkcs12(self, data):
        count = 0
        for password in self.cracker.yield_passwords():
            count += 1
            try:
                crypto.load_pkcs12(data, password.encode())
                return {'status': 'success', 'password': password, 'attempts': count, 'type': 'PKCS#12 Cert'}
            except crypto.Error:
                continue
            except Exception:
                continue
        return {'status': 'failed', 'attempts': count}
        
    def _crack_pem(self, data):
        count = 0
        # Check if unencrypted first
        try:
            crypto.load_privatekey(crypto.FILETYPE_PEM, data, passphrase=None)
            return {'status': 'success', 'password': 'N/A (Sem senha)', 'attempts': 0, 'type': 'Private Key (Open)'}
        except:
            pass # Continua

        for password in self.cracker.yield_passwords():
            count += 1
            try:
                crypto.load_privatekey(crypto.FILETYPE_PEM, data, passphrase=password.encode())
                return {'status': 'success', 'password': password, 'attempts': count, 'type': 'Private Key (Encrypted)'}
            except crypto.Error:
                continue
            except Exception:
                continue
        return {'status': 'failed', 'attempts': count}

    def _crack_pdf(self, data):
        count = 0
        f = io.BytesIO(data)
        try:
            reader = pypdf.PdfReader(f)
            if not reader.is_encrypted:
                return {'status': 'success', 'password': 'N/A (Sem senha)', 'attempts': 0}
            
            for password in self.cracker.yield_passwords():
                count += 1
                try:
                    res = reader.decrypt(password)
                    if res in [1, 2]: # 1=Owner pass, 2=User pass
                         return {'status': 'success', 'password': password, 'attempts': count, 'type': 'PDF Document'}
                except:
                    continue
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

        return {'status': 'failed', 'attempts': count}

    def _crack_zip_memory(self, mk_bytes):
        count = 0
        f = io.BytesIO(mk_bytes)
        try:
            z = zipfile.ZipFile(f)
            if not z.namelist(): return {'status': 'error', 'message': 'Zip vazio'}
            target = z.namelist()[0]
            
            for password in self.cracker.yield_passwords():
                count += 1
                try:
                    z.read(target, pwd=password.encode())
                    return {'status': 'success', 'password': password, 'attempts': count, 'type': 'ZIP Archive'}
                except:
                    continue
        except Exception as e:
             return {'status': 'error', 'message': str(e)}
        return {'status': 'failed', 'attempts': count}

    def _crack_zip(self, path):
         return self._crack_zip_memory(open(path, 'rb').read())
