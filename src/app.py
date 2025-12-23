from flask import Flask, render_template, request, send_file, session, jsonify
import os
from scanner import VulnerabilityScanner
from reporter import generate_pdf_report
from modules.forensics_engine import ForensicsEngine
from modules.header_analyzer import EmailHeaderAnalyzer
from modules.log_analyzer import LogSentinel
from modules.hash_cracker import HashCracker
from modules.code_analyzer import CodeHunter
from modules.cms_scanner import CMSDetective
import tempfile

# Initialize Modules
forensics_lab = ForensicsEngine()
email_hunter = EmailHeaderAnalyzer()
log_sentinel = LogSentinel()
hash_cracker = HashCracker()
code_hunter = CodeHunter()
cms_detective = CMSDetective()

app = Flask(__name__)
# Use a stable key so sessions survive server restarts (better for UX)
app.secret_key = "VALIDADOR_SEC_INTERNAL_KEY_V2_STATIC"

# Increase Max Upload Size to 1GB (Explicit limit)
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024

# Temporarily disabled to debug 413 error
# @app.errorhandler(413)
# def request_entity_too_large(error):
#     return jsonify({'error': 'File/Code too large (Server Limit Exceeded)'}), 413

# --- SECURITY: Rate Limiting ---
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

@limiter.request_filter
def ip_whitelist():
    # Permitir acesso ilimitado para localhost (onde a ferramenta roda)
    return request.remote_addr == "127.0.0.1" or request.remote_addr == "::1"

# Ensure templates directory exists if running flat
template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
if not os.path.exists(template_dir):
    os.makedirs(template_dir)
app.template_folder = template_dir

# --- SECURITY CHECK ---
import sys
import hashlib
import getpass

AUTHORIZED_HASH = "fc66f021c67d064c1490a12b5a4d4d2f5167ca692a16ca12f1f3a4cda29a6fa9" # sha256("long")

def check_auth():
    # 1. Check Env Var (Passed by INICIAR.bat)
    if os.environ.get('VALIDADOR_HASH') == AUTHORIZED_HASH:
        return True
    
    # 2. Fallback: Check args (legacy)
    if len(sys.argv) > 1 and sys.argv[1] == AUTHORIZED_HASH:
        return True
    
    # 3. If not, prompt user
    print("\n" + "="*50)
    print("[!] SISTEMA BLOQUEADO")
    print("="*50)
    print("Este sistema requer autorizacao para iniciar.")
    
    try:
        pwd = getpass.getpass("Digite a senha de acesso: ")
        if hashlib.sha256(pwd.encode()).hexdigest() == AUTHORIZED_HASH:
            print("[OK] Acesso Autorizado!")
            return True
    except Exception:
        pass
    
    print("[X] Acesso Negado.")
    return False

if not check_auth():
    # AUTENTICAÇÃO DESABILITADA PARA USO LOCAL
    # Descomente a linha abaixo para habilitar proteção por senha
    # sys.exit(1)
    pass  # Sistema liberado
# --- END SECURITY CHECK ---

# --- INTEGRITY CHECK ---
from integrity_check import verify_integrity, block_execution_alert

is_valid, error = verify_integrity()
if not is_valid:
    block_execution_alert()
    print(f"\n[CRITICO] {error}")
    print("[ACAO] Restaure os arquivos da fonte original confiavel.\n")
    sys.exit(1)

print("[OK] Integridade verificada - Sistema integro")
# --- END INTEGRITY CHECK ---

# --- SECURITY HEADERS ---
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; img-src 'self' data: https:; frame-src 'self' https:;"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response
# --- END SECURITY HEADERS ---


@app.route('/', methods=['GET', 'POST'])
@limiter.limit("5 per minute") # Rate Limit custom for scan
def index():
    report_file = None
    target_url = None
    results = []
    network_info = {}  # Initialize for GET requests
    error_msg = None
    
    # Generate CSRF Token for GET
    if 'csrf_token' not in session:
        session['csrf_token'] = os.urandom(24).hex()
    
    if request.method == 'POST':
        # 1. CSRF Check
        token = request.form.get('csrf_token')
        if not token or token != session.get('csrf_token'):
            return "Erro de Segurança: Token CSRF inválido.", 403

        target_url = request.form.get('url')
        
        # 2. Input Sanitization (Fix NoSQL/Injection)
        if not target_url or not isinstance(target_url, str):
             error_msg = "URL inválida."
        else:
            # Force string and strip weird chars
            target_url = str(target_url).strip()
            # Simple validation
            if not target_url.startswith(('http://', 'https://')):
                 # Auto-fix or reject? Let's just prepend http if missing scheme, but usually better to reject input if weird.
                 # Using the same logic as before but ensuring it IS a string.
                 pass
            
            # Reject json/dict injection attempts explicitly
            if '{' in target_url or '}' in target_url:
                 error_msg = "Caracteres proibidos na URL."
                 target_url = None

        if target_url and not error_msg:
            # Reset progress
            global progress_status
            progress_status = "Iniciando Scan..."
            
            def update_status(msg):
                global progress_status
                progress_status = msg
                
            # Smart URL Handling
            force_dual = request.form.get('force_dual') == 'on'
            urls_to_scan = []
            
            # Helper to strip scheme
            target_stripped = target_url.replace('http://', '').replace('https://', '')

            # Logic: If force_dual is ON OR no scheme provided -> Scan both. Else -> Scan as is.
            if force_dual or not target_url.startswith(('http://', 'https://')):
                 urls_to_scan = [f'http://{target_stripped}', f'https://{target_stripped}']
            else:
                urls_to_scan = [target_url]

            all_results = []
            for i, url in enumerate(urls_to_scan):
                # Update global status regarding the current target
                update_status(f"Iniciando Scan {i+1}/{len(urls_to_scan)}: {url}")
                
                # Scan instance
                # Captura opcoes do formulario
                options = {
                    'force_dual': request.form.get('force_dual') == 'on',
                    'deep_fuzzing': request.form.get('deep_fuzzing') == 'on',
                    'time_sqli': request.form.get('time_sqli') == 'on',
                    'use_nuclei': request.form.get('use_nuclei') == 'on',
                    'use_subfinder': request.form.get('use_subfinder') == 'on',
                    'allow_invasive': request.form.get('allow_invasive') == 'on'
                }
                scanner = VulnerabilityScanner(url, options=options, progress_callback=update_status)
                scan_results = scanner.run_all()
                
                # Tag results with the specific URL scanned if we are doing dual scan
                if len(urls_to_scan) > 1:
                    for res in scan_results:
                        res['vulnerability'] = f"[{url.split(':')[0].upper()}] {res['vulnerability']}"
                
                all_results.extend(scan_results)
            
            results = all_results
            
            # Sort Results: Fails First (Critical->Info), then Passes (Critical->Info)
            severity_order = {
                'Critical': 0,
                'High': 1,
                'Medium': 2,
                'Low': 3,
                'Info': 4
            }
            
            def get_sort_key(res):
                # 1. Status Priority: Vulnerable/Warning/Error comes BEFORE Safe/Info
                status = res.get('status', 'Info')
                is_safe = 1 if status in ['Safe', 'Info'] else 0
                
                # 2. Severity Weight
                sev_str = res.get('severity', 'Info')
                weight = 99
                for k, v in severity_order.items():
                    if k in sev_str:
                        weight = v
                        break
                
                return (is_safe, weight)

            results.sort(key=get_sort_key)

            # Calculate Summary Stats for Dashboard
            summary_stats = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
            category_stats = {}
            
            for r in results:
                # Severity Stats
                s = r.get('severity', 'Info')
                if 'Critical' in s: summary_stats['Critical'] += 1
                elif 'High' in s: summary_stats['High'] += 1
                elif 'Medium' in s: summary_stats['Medium'] += 1
                elif 'Low' in s: summary_stats['Low'] += 1
                else: summary_stats['Info'] += 1
                
                # Category Stats
                cat = r.get('category', 'Outros')
                category_stats[cat] = category_stats.get(cat, 0) + 1
            

            # Generate Report (PDF)
            # In a real app we might handle file cleanup better or use a stable path
            # For this local tool, we overwrite 'latest_report.pdf'
            report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'latest_report.pdf')
            
            # Extract network info from scanner
            network_info = getattr(scanner, 'network_info', {})
            
            generate_pdf_report(results, target_url, report_path, network_info)
            report_file = 'latest_report.pdf'
            
            # Generate Report (DOCX) - [NEW]
            try:
                report_docx_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'latest_report.docx')
                from modules.docx_reporter import generate_docx_report
                generate_docx_report(results, target_url, report_docx_path, network_info)
            except Exception as e:
                print(f"Failed to generate DOCX: {e}")

            
    from datetime import datetime
    return render_template('index.html', 
                         results=results, 
                         target_url=target_url, 
                         report_file=report_file, 
                         report_date=datetime.now().strftime("%d/%m/%Y %H:%M"), 
                         summary=locals().get('summary_stats'), 
                         cats=locals().get('category_stats'),
                         network_info=network_info,
                         csrf_token=session['csrf_token'],
                         error=error_msg)

@app.route('/download')
def download_default():
    return download_format('pdf')

@app.route('/download/<format>')
def download_format(format):
    if format == 'pdf':
        filename = 'latest_report.pdf'
        mime = 'application/pdf'
    elif format == 'docx':
        filename = 'latest_report.docx'
        mime = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    else:
        return "Format not supported", 400
        
    report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    if os.path.exists(report_path):
        return send_file(report_path, as_attachment=True, mimetype=mime, download_name=filename)
    return "Report not found", 404

# Global progress state
progress_status = "Aguardando inicio..."

@app.route('/progress')
def get_progress():
    global progress_status
    return {'status': progress_status}

@app.route('/shutdown', methods=['POST'])
def shutdown():
    # Shutdown the server gracefully
    print("Shutting down server...")
    
    # Schedule the kill for 1 second later to allow response to be sent
    import threading
    import time
    def kill_server():
        time.sleep(1)
        os._exit(0)
        
    threading.Thread(target=kill_server).start()
    return "Server shutting down... You can close this tab."

# ==========================================
# ROTAS OSINT
# ==========================================

@app.route('/osint')
def osint_page():
    """Renderiza interface OSINT"""
    # Generate CSRF token
    if 'csrf_token' not in session:
        session['csrf_token'] = os.urandom(24).hex()
    
    import time
    return render_template('osint.html', csrf_token=session['csrf_token'], timestamp=int(time.time()))

# Cache global para resultados temporários (substitui session em streaming)
OSINT_RESULTS_CACHE = {}

@app.route('/osint/execute', methods=['POST'])
@limiter.limit("3 per minute")
def osint_execute():
    """Executa investigação OSINT com streaming de progresso"""
    from flask import Response, stream_with_context
    from modules.osint_engine import OsintEngine
    import json
    import time
    import uuid
    
    # CSRF Check
    token = request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        return "Erro de Segurança: Token CSRF inválido.", 403
    
    # Get parameters
    mission_type = request.form.get('mission_type')
    target = request.form.get('target')
    
    if not mission_type or not target:
        return "Parâmetros inválidos", 400
    
    # Build options from form
    options = {}
    for key in request.form:
        if key not in ['csrf_token', 'mission_type', 'target']:
            options[key] = request.form.get(key) == 'on'
    
    def generate():
        """Generator para streaming de progresso"""
        try:
            # Create engine
            engine = OsintEngine(mission_type, target, options)
            
            # Progress callback
            def progress_callback(percent, message):
                data = json.dumps({
                    'progress': percent,
                    'message': message
                })
                return data + '\n'
            
            # Stream initial progress
            yield progress_callback(0, 'Iniciando investigação...')
            time.sleep(0.1)  # Small delay for UI
            
            # Set callback
            engine.set_progress_callback(lambda p, m: None)  # Internal callback disabled for streaming
            
            # Execute mission (this will take time)
            results = engine.execute_mission()
            
            # Stream intermediate progress manually
            yield progress_callback(25, 'Coletando dados...')
            yield progress_callback(50, 'Analisando informações...')
            yield progress_callback(75, 'Gerando relatório...')
            
            # Store results in SERVER CACHE instead of session
            report_id = str(uuid.uuid4())
            OSINT_RESULTS_CACHE[report_id] = results
            
            # Send final results including report_id
            final_data = json.dumps({
                'done': True,
                'results': results,
                'report_id': report_id
            })
            yield final_data + '\n'
            
        except Exception as e:
            error_data = json.dumps({
                'done': True,
                'error': str(e),
                'results': {
                    'findings': [],
                    'summary': {'error': str(e)},
                    'recommendations': []
                }
            })
            yield error_data + '\n'
    
    return Response(
        stream_with_context(generate()),
        mimetype='application/x-ndjson'  # Newline-delimited JSON
    )

@app.route('/osint/report/<format>')
def osint_report(format):
    """Gera relatório em PDF ou JSON"""
    from flask import jsonify, send_file
    import io
    
    # Get ID from query
    report_id = request.args.get('id')
    
    # Try cache first, then session (fallback for old flow)
    results = None
    if report_id and report_id in OSINT_RESULTS_CACHE:
        results = OSINT_RESULTS_CACHE[report_id]
    else:
        results = session.get('last_osint_results')
    
    if not results:
        # Debug: check cache keys
        return f"Relatório não encontrado. ID: {report_id}. Cache Keys: {list(OSINT_RESULTS_CACHE.keys())}", 404
    
    if format == 'json':
        return jsonify(results)
    
    elif format == 'pdf':
        try:
            from fpdf import FPDF
            
            class PDF(FPDF):
                def header(self):
                    self.set_font('Arial', 'B', 15)
                    self.cell(0, 10, 'Relatório OSINT - Validador SEC', 0, 1, 'C')
                    self.ln(5)
                
                def footer(self):
                    self.set_y(-15)
                    self.set_font('Arial', 'I', 8)
                    self.cell(0, 10, f'Página {self.page_no()}', 0, 0, 'C')
            
            pdf = PDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)
            
            # Helper para limpar emojis e chars inválidos de forma robusta
            clean = lambda s: str(s).replace('⚠️', '[!]').replace('✅', '[OK]').replace('❌', '[X]').replace('⚡', '[RUN]').replace('🔒', '[LOCK]').replace('🔓', '[OPEN]').encode('latin-1', 'replace').decode('latin-1')
            
            # Target
            pdf.set_font("Arial", 'B', 12)
            pdf.cell(0, 10, clean(f"Alvo: {results.get('target', 'N/A')}"), 0, 1)
            pdf.ln(5)
            
            # Summary
            if 'summary' in results:
                pdf.set_font("Arial", 'B', 14)
                pdf.cell(0, 10, clean("Resumo"), 0, 1)
                pdf.set_font("Arial", size=10)
                for k, v in results['summary'].items():
                    pdf.cell(0, 8, clean(f"{k}: {v}"), 0, 1)
                pdf.ln(5)
            
            # Finds
            pdf.set_font("Arial", 'B', 14)
            pdf.cell(0, 10, clean("Detalhes"), 0, 1)
            pdf.set_font("Arial", size=10)
            
            for finding in results.get('findings', []):
                title = finding.get('title', 'Finding')
                desc = finding.get('description', '')
                
                pdf.set_font("Arial", 'B', 11)
                pdf.cell(0, 8, clean(f"- {title}"), 0, 1)
                
                pdf.set_font("Arial", size=10)
                pdf.multi_cell(0, 6, clean(desc))
                pdf.ln(3)

            # Output to memory
            pdf_output = io.BytesIO()
            pdf_string = pdf.output(dest='S').encode('latin-1', 'replace') # Safe encode
            pdf_output.write(pdf_string) 
            pdf_output.seek(0)
            
            return send_file(
                pdf_output,
                mimetype='application/pdf',
                as_attachment=True,
                download_name=f'osint_report_{results.get("target","scan")}.pdf'
            )
            
        except Exception as e:
            return jsonify({
                'error': 'Erro ao gerar PDF',
                'details': str(e)  # Retorna erro detalhado para debug
            }), 500
    
    else:
        return "Formato inválido", 400


@app.route('/forensics')
def forensics_page():
    """Página principal do Laboratório Forense"""
    import time
    return render_template('forensics.html', timestamp=int(time.time()))

@app.route('/forensics/analyze', methods=['POST'])
@limiter.limit("10 per minute")
def forensics_analyze():
    """Analisa arquivo (Hash + Metadados)"""
    from flask import jsonify
    if 'file' not in request.files:
        return jsonify({'error': 'Nenhum arquivo enviado'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Nome de arquivo inválido'}), 400
        
    try:
        result = forensics_lab.analyze_file(file.stream, file.filename)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/forensics/scrub', methods=['POST'])
@limiter.limit("5 per minute")
def forensics_scrub():
    """Limpa ou Altera metadados de arquivos (Privacidade)"""
    print("\n=== ROTA /forensics/scrub CHAMADA ===")
    
    if 'file' not in request.files:
        return "Erro: Nenhum arquivo enviado", 400
    
    file = request.files['file']
    print(f"Arquivo recebido: {file.filename}")
    
    # Log de TODOS os campos do formulário
    print(f"Form data recebido: {dict(request.form)}")
    
    # Capturar opções de Spoofing (se houver)
    custom_meta = {}
    if request.form.get('spoof_make'): 
        custom_meta['make'] = request.form['spoof_make']
        print(f"  → Make: {custom_meta['make']}")
    
    if request.form.get('spoof_device'): 
        custom_meta['device'] = request.form['spoof_device']
        print(f"  → Device: {custom_meta['device']}")
    
    if request.form.get('spoof_date'):
        # Converter input datetime-local (YYYY-MM-DDTHH:MM) para EXIF (YYYY:MM:DD HH:MM:SS)
        d = request.form['spoof_date'] # Ex: 2025-12-25T14:30
        custom_meta['date'] = f"{d.replace('T', ' ').replace('-', ':')}:00"
        print(f"  → Data: {d} → {custom_meta['date']}")
    
    if request.form.get('spoof_lat') and request.form.get('spoof_lon'):
        custom_meta['gps_lat'] = request.form['spoof_lat']
        custom_meta['gps_lon'] = request.form['spoof_lon']
        print(f"  → GPS: {custom_meta['gps_lat']}, {custom_meta['gps_lon']}")

    if request.form.get('spoof_software'):
        custom_meta['software'] = request.form['spoof_software']
        print(f"  → Software: {custom_meta['software']}")
    
    print(f"custom_meta final: {custom_meta}")
    print("=== Chamando forensics_lab.scrub_file ===\n")

    try:
        cleaned_stream, new_name = forensics_lab.scrub_file(file.stream, file.filename, custom_meta)
        
        return send_file(
            cleaned_stream,
            as_attachment=True,
            download_name=new_name,
            mimetype='application/octet-stream'
        )
    except Exception as e:
        return f"Erro ao processar: {str(e)}", 500

@app.route('/proxy/cep/<cep>')
def proxy_cep(cep):
    """Proxy para BrasilAPI (Bypass CORS)"""
    try:
        import requests
        resp = requests.get(f"https://brasilapi.com.br/api/cep/v2/{cep}", timeout=5)
        if resp.status_code != 200:
            return jsonify({"error": "CEP não encontrado ou erro na API"}), 404
        return jsonify(resp.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/proxy/nominatim')
def proxy_nominatim():
    """Proxy para Nominatim (OSM) com User-Agent correto"""
    query = request.args.get('q')
    if not query: return jsonify([]), 400
    try:
        import requests
        # Nominatim EXIGE User-Agent
        headers = {'User-Agent': 'CyberLab-Forensics/1.0'}
        resp = requests.get("https://nominatim.openstreetmap.org/search", 
                          params={'format': 'json', 'limit': '1', 'q': query}, 
                          headers=headers, timeout=10)
        return jsonify(resp.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# --- EMAIL HUNTER ROUTES ---
@app.route('/tools/email')
def tool_email_view():
    return render_template('email_analyzer.html')

@app.route('/tools/email-analyze', methods=['POST'])
@limiter.limit("20 per minute")
def tool_email_api():
    header_text = request.form.get('header')
    if not header_text:
        return jsonify({'error': 'No header provided'}), 400
    
    result = email_hunter.analyze(header_text)
    return jsonify(result)

# --- LOG SENTINEL ROUTES ---
@app.route('/tools/log')
def tool_log_view():
    return render_template('log_sentinel.html')

@app.route('/tools/log-analyze', methods=['POST'])
@limiter.limit("5 per minute")
def tool_log_api():
    if 'logfile' not in request.files:
        return jsonify({'error': 'Nenhum arquivo enviado'}), 400
    file = request.files['logfile']
    content = file.read().decode('utf-8', errors='ignore')
    report = log_sentinel.analyze(content)
    return jsonify(report)

# --- HASH CRACKER ROUTES ---
@app.route('/tools/hash')
def tool_hash_view():
    return render_template('hash_cracker.html')

@app.route('/tools/hash-crack', methods=['POST'])
@limiter.limit("20 per minute")
def tool_hash_api():
    h = request.form.get('hash')
    if not h: return jsonify({'error': 'Hash vazio'}), 400
    return jsonify(hash_cracker.crack(h))

# --- FILE CRACKER ROUTES ---
@app.route('/tools/file-crack', methods=['POST'])
@limiter.limit("5 per minute")
def tool_file_crack():
    if 'file' not in request.files:
        return jsonify({'error': 'Nenhum arquivo enviado'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Nome de arquivo vazio'}), 400
        
    # Read bytes
    file_bytes = file.read()
    
    # Process
    from modules.file_cracker import FileCracker
    fc = FileCracker() # Instanciar aqui ou no escopo global (melhor aqui pra não carregar se não usar)

    try:
        result = fc.crack_file(file.filename, file_bytes)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- CODE HUNTER ROUTES ---
@app.route('/tools/code')
def tool_code_view():
    return render_template('code_hunter.html')

@app.route('/tools/code-analyze', methods=['POST'])
@limiter.exempt  # Exempt from rate limiting for large payloads
def tool_code_api():
    code = request.form.get('code', '')
    return jsonify(code_hunter.analyze(code))

@app.route('/tools/code-analyze-file', methods=['POST'])
@limiter.exempt
def tool_code_file_api():
    """Analyze code from uploaded file - bypasses form data size limits"""
    if 'file' not in request.files:
        return jsonify({'error': 'Nenhum arquivo enviado'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Nome de arquivo inválido'}), 400
    
    try:
        # Read file content as text
        code = file.read().decode('utf-8', errors='ignore')
        return jsonify(code_hunter.analyze(code))
    except Exception as e:
        return jsonify({'error': f'Erro ao processar arquivo: {str(e)}'}), 500

# --- CMS DETECTIVE ROUTES ---
@app.route('/tools/cms')
def tool_cms_view():
    return render_template('cms_detective.html')

@app.route('/tools/cms-scan', methods=['POST'])
def tool_cms_api():
    url = request.form.get('url', '')
    return jsonify(cms_detective.scan(url))

if __name__ == '__main__':
    app.run(debug=True, port=5000)
