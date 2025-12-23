"""
Módulo Forense Digital (Cyber Lab)
Responsável por análise de artefatos, esteganografia básica e metadados.
"""

import hashlib
import io
import os
import base64
from typing import Dict, Any, Tuple
from PIL import Image, ExifTags
from datetime import datetime
import pypdf

class ForensicsEngine:
    """Motor de análise forense de arquivos"""
    
    def __init__(self):
        pass
        
    def analyze_file(self, file_stream, filename: str) -> Dict[str, Any]:
        """
        Analisa um arquivo enviado (wrapper principal)
        """
        # Reset pointer
        file_stream.seek(0)
        content = file_stream.read()
        size = len(content)
        filesize_mb = size / (1024 * 1024)
        
        # 1. Cálculo de Hashes (Fingerprinting)
        md5 = hashlib.md5(content).hexdigest()
        sha1 = hashlib.sha1(content).hexdigest()
        sha256 = hashlib.sha256(content).hexdigest()
        
        result = {
            'filename': filename,
            'size_bytes': size,
            'size_formatted': f"{filesize_mb:.2f} MB",
            'hashes': {
                'md5': md5,
                'sha1': sha1,
                'sha256': sha256
            },
            'type': 'unknown',
            'metadata': {},
            'threat_intel': {
                'virustotal': f"https://www.virustotal.com/gui/file/{sha256}",
                'talos': f"https://talosintelligence.com/reputation_center/lookup?search={sha256}",
                'hybrid_analysis': f"https://www.hybrid-analysis.com/search?query={sha256}"
            }
        }
        
        # 2. Detecção de Tipo e Análise Específica
        ext = filename.lower().split('.')[-1] if '.' in filename else ''
        
        if ext in ['jpg', 'jpeg', 'png', 'tiff', 'webp']:
            result['type'] = 'image'
            img_data = self._analyze_image(content)
            result['metadata'] = img_data
            
        elif ext == 'pdf':
            result['type'] = 'document'
            pdf_data = self._analyze_pdf(content)
            result['metadata'] = pdf_data
            
            
        return result

    def _analyze_image(self, content: bytes) -> Dict[str, Any]:
        """Extrai metadados EXIF de imagens"""
        meta = {
            'has_exif': False,
            'gps': None,
            'device': None,
            'date_original': None,
            'software': None,
            'dimensions': None
        }
        
        try:
            image = Image.open(io.BytesIO(content))
            meta['dimensions'] = f"{image.width}x{image.height}"
            meta['format'] = image.format
            meta['mode'] = image.mode
            
            exif = image._getexif()
            if not exif:
                return meta
                
            meta['has_exif'] = True
            
            # Map EXIF tags to readable names
            exif_data = {
                ExifTags.TAGS.get(k, k): v
                for k, v in exif.items()
            }
            
            # Extrair dados de interesse
            make = str(exif_data.get('Make', '')).strip()
            model = str(exif_data.get('Model', '')).strip()
            
            meta['make'] = make
            meta['model'] = model
            meta['device'] = f"{make} {model}".strip()
            
            meta['software'] = str(exif_data.get('Software', '')).strip()
            meta['date_original'] = exif_data.get('DateTimeOriginal') or exif_data.get('DateTime')
            
            # GPS Extraction
            if 'GPSInfo' in exif_data:
                gps_info = exif_data['GPSInfo']
                lat = self._get_decimal_coords(gps_info, 'GPSLatitude', 'GPSLatitudeRef')
                lon = self._get_decimal_coords(gps_info, 'GPSLongitude', 'GPSLongitudeRef')
                
                if lat and lon:
                    meta['gps'] = {
                        'latitude': lat,
                        'longitude': lon,
                        'maps_link': f"https://www.google.com/maps?q={lat},{lon}"
                    }
                    
        except Exception as e:
            meta['error'] = str(e)
            
        return meta
    
    def _analyze_pdf(self, content: bytes) -> Dict[str, Any]:
        """Extrai metadados básicos de arquivos PDF"""
        meta = {}
        try:
            reader = pypdf.PdfReader(io.BytesIO(content))
            info = reader.metadata
            
            if info:
                # Mapear campos comuns
                if info.author: meta['Author'] = info.author
                if info.creator: meta['Creator'] = info.creator # Software usado
                if info.producer: meta['Producer'] = info.producer # Biblioteca PDF
                if info.title: meta['Title'] = info.title
                if info.subject: meta['Subject'] = info.subject
                
                # Data de criação/modificação (formato D:YYYYMMDD...)
                if '/CreationDate' in info:
                    meta['Creation Date'] = info['/CreationDate'].replace('D:', '').split('+')[0]
                if '/ModDate' in info:
                    meta['Modification Date'] = info['/ModDate'].replace('D:', '').split('+')[0]

            meta['Pages'] = len(reader.pages)
            meta['Encrypted'] = reader.is_encrypted
            
            # Tentar detectar JavaScript embutido (básico)
            if '/JavaScript' in str(reader.trailer):
                 meta['Suspicious'] = "⚠️ JavaScript detected within PDF structure"

        except Exception as e:
            meta['error'] = f"PDF Error: {str(e)}"
            
        return meta

    def _generate_lsb_analysis(self, content: bytes) -> str:
        """Gera uma visualização da camada LSB (Bit Menos Significativo) para detectar esteganografia"""
        try:
            img = Image.open(io.BytesIO(content)).convert('RGB')
            # Extrair LSB: Se bit é 1 -> 255 (Branco), se 0 -> 0 (Preto)
            # Isso revela 'ruído' onde há dados escondidos
            lsb_img = img.point(lambda p: (p & 1) * 255)
            
            # Salvar em buffer para base64
            buffered = io.BytesIO()
            lsb_img.save(buffered, format="PNG")
            img_str = base64.b64encode(buffered.getvalue()).decode()
            return f"data:image/png;base64,{img_str}"
        except Exception:
            return None

    def _analyze_image(self, content: bytes) -> Dict[str, Any]:
        """Extrai metadados EXIF de imagens"""
        meta = {
            'device': None,
            'date_original': None,
            'gps': None,
            'stego_analysis': self._generate_lsb_analysis(content)
        }
        
        try:
            img = Image.open(io.BytesIO(content))
            exif = img._getexif()
            
            if exif:
                # Mapear tags numéricas para nomes legíveis
                exif_data = {
                    ExifTags.TAGS.get(key, key): val 
                    for key, val in exif.items()
                }
                
                # Device Info
                make = exif_data.get('Make', '').strip()
                model = exif_data.get('Model', '').strip()
                if make or model:
                    meta['device'] = f"{make} {model}".strip()
                    
                # Date Info
                if 'DateTimeOriginal' in exif_data:
                    meta['date_original'] = exif_data['DateTimeOriginal']
                
                # GPS Info
                # 34853 é a tag para GPSInfo
                gps_info = exif.get(34853)
                if gps_info:
                    lat = self._get_decimal_coords(gps_info, 'GPSLatitude', 'GPSLatitudeRef')
                    lon = self._get_decimal_coords(gps_info, 'GPSLongitude', 'GPSLongitudeRef')
                    
                    if lat and lon:
                        meta['gps'] = {
                            'latitude': lat,
                            'longitude': lon,
                            'maps_link': f"https://www.google.com/maps?q={lat},{lon}"
                        }
                    
        except Exception as e:
            meta['error'] = str(e)
            
        return meta

    def _get_decimal_coords(self, gps_info, lat_long_tag, ref_tag):
        """Converte coordenadas DMS (Graus, Min, Seg) para Decimal"""
        try:
            # Pegar tags
            # GPSLatitude = 2, GPSLatitudeRef = 1
            # GPSLongitude = 4, GPSLongitudeRef = 3
            
            tag_ids = {
                'GPSLatitudeRef': 1,
                'GPSLatitude': 2,
                'GPSLongitudeRef': 3,
                'GPSLongitude': 4
            }
            
            ref = gps_info.get(tag_ids[ref_tag])
            coords = gps_info.get(tag_ids[lat_long_tag])
            
            if not coords or not ref:
                return None
                
            degrees = coords[0]
            minutes = coords[1]
            seconds = coords[2]
            
            decimal = float(degrees) + (float(minutes) / 60.0) + (float(seconds) / 3600.0)
            
            if ref in ['S', 'W']:
                decimal = -decimal
                
            return decimal
        except:
            return None

    def scrub_file(self, file_stream, filename: str, custom_meta: Dict[str, str] = None) -> Tuple[io.BytesIO, str]:
        """
        Remove ou Altera metadados de arquivos (Sanitization / Spoofing)
        Retorna (buffer, novonome)
        """
        file_stream.seek(0)
        content = file_stream.read()
        
        # Validação crítica
        if not content:
            raise ValueError("Arquivo vazio recebido")
        
        # Detectar arquivos corrompidos de tentativas anteriores
        if filename.count('spoofed_') > 1:
            raise ValueError("❌ Este arquivo foi processado múltiplas vezes e está corrompido. Use a IMAGEM ORIGINAL.")
        
        print(f"\n>>> SCRUB: Arquivo={filename}, Tamanho={len(content)} bytes")
        
        ext = filename.lower().split('.')[-1]
        
        output = io.BytesIO()
        new_filename = f"clean_{filename}"
        
        if ext in ['jpg', 'jpeg', 'png', 'webp']:
            try:
                # Testar se é uma imagem válida primeiro
                img = Image.open(io.BytesIO(content))
                img.verify()  # Verifica integridade
                
                # Reabrir (verify() invalida o objeto)
                img = Image.open(io.BytesIO(content))
                print(f"✓ Imagem válida: {img.format} {img.size}")
                
                # Se não tiver custom_meta, comportamento padrão é remover tudo
                if not custom_meta:
                    data = list(img.getdata())
                    clean_img = Image.new(img.mode, img.size)
                    clean_img.putdata(data)
                    clean_img.save(output, format=img.format or 'PNG')
                
                else:
                    # MODO SPOOFING AVANÇADO
                    print(f"\n=== DEBUG SPOOFING ===")
                    print(f"custom_meta recebido: {custom_meta}")
                    
                    # NÃO modificar o EXIF original aqui
                    # Tudo será feito na seção de EXIF Limpo abaixo
                    
                    # Salvar imagem com novo EXIF
                    print(f"Salvando imagem com EXIF modificado...")
                    
                    save_format = img.format
                    output_img = img
                    
                    # Quando há spoofing, criar EXIF completamente limpo (evita conflitos de tuplas/tipos)
                    from PIL.Image import Exif
                    save_exif = Exif()
                    
                    # Copiar apenas os valores que editamos
                    if custom_meta.get('make'):
                        save_exif[0x010f] = custom_meta['make']
                    if custom_meta.get('device'):
                        save_exif[0x0110] = custom_meta['device']
                    if custom_meta.get('software'):
                        save_exif[0x0131] = custom_meta['software']
                    if custom_meta.get('date'):
                        save_exif[0x0132] = custom_meta['date']
                        save_exif[0x9003] = custom_meta['date']
                        save_exif[0x9004] = custom_meta['date']
                    
                    '''
                    # Recriar GPS IFD limpo
                    if custom_meta.get('gps_lat') and custom_meta.get('gps_lon'):
                        lat = float(custom_meta['gps_lat'])
                        lon = float(custom_meta['gps_lon'])
                        gps_ifd_clean = {
                            1: 'N' if lat >= 0 else 'S',
                            2: self._to_dms(abs(lat)),
                            3: 'E' if lon >= 0 else 'W',
                            4: self._to_dms(abs(lon))
                        }
                        save_exif[0x8825] = gps_ifd_clean
                        print(f"✓ GPS adicionado ao EXIF limpo")
                    '''
                    
                    # PNG precisa conversão para JPEG
                    if img.format == 'PNG':
                        print(f"⚠️ PNG detectado - convertendo para JPEG para suportar EXIF completo")
                        
                        # Converter para RGB se necessário (JPEG não suporta transparência)
                        if img.mode in ('RGBA', 'P', 'LA'):
                            rgb_img = Image.new('RGB', img.size, (255, 255, 255))
                            if img.mode in ('RGBA', 'LA'):
                                rgb_img.paste(img, (0, 0), img.split()[-1])
                            else:
                                rgb_img.paste(img.convert('RGBA'), (0, 0))
                            output_img = rgb_img
                        elif img.mode != 'RGB':
                            output_img = img.convert('RGB')
                        
                        save_format = 'JPEG'
                        new_filename = f"spoofed_{filename.rsplit('.', 1)[0]}.jpg"
                        print(f"✓ Convertido {img.mode} → RGB")
                    
                    # Salvar com EXIF limpo
                    output_img.save(output, format=save_format or 'JPEG', exif=save_exif, quality=95)
                    print(f"✓ Imagem salva como: {new_filename}")
                    print(f"=== FIM DEBUG ===\n")
                
                output.seek(0)
                return output, new_filename
                
            except Exception as e:
                print(f"Erro no scrub: {e}")
                output.write(content)
                output.seek(0)
                return output, filename
        
        output.write(content)
        output.seek(0)
        return output, filename

    def _to_dms(self, value: float):
        """Converte float para tupla de racionais (Deg, Min, Sec) para EXIF"""
        deg = int(value)
        min_val = (value - deg) * 60
        mins = int(min_val)
        secs = round((min_val - mins) * 60 * 10000) # precisão alta
        
        # Formato Pillow IFDRacional: (numerador, denominador)
        return ((deg, 1), (mins, 1), (secs, 10000))
