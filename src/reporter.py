from fpdf import FPDF
from datetime import datetime

class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 16)
        self.cell(0, 10, 'Relatório Técnico de Segurança Web', 0, 1, 'C')
        self.set_font('Arial', 'I', 10)
        self.cell(0, 5, 'Pentest Automatizado - Análise de Vulnerabilidades', 0, 1, 'C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Gerado em {datetime.now().strftime("%d/%m/%Y %H:%M")} - ValidadorSec v1.0 | Pagina ' + str(self.page_no()) + '/{nb}', 0, 0, 'C')

def generate_pdf_report(results, target_url, output_path, network_info=None):
    pdf = PDFReport()
    pdf.alias_nb_pages()
    pdf.add_page()

    # Executive Summary / Metodologia
    pdf.set_font('Arial', 'B', 14)
    pdf.cell(0, 10, '1. Resumo Executivo', 0, 1)
    pdf.set_font('Arial', '', 11)
    pdf.multi_cell(0, 6, f"Alvo da Analise: {target_url}\nData do Teste: {datetime.now().strftime('%d/%m/%Y')}\n\nEste relatorio apresenta os resultados de uma analise de seguranca automatizada, focada em vulnerabilidades comuns (OWASP Top 10) e configuracoes incorretas de servidor.")
    
    # Network Technical Information Panel
    if network_info:
        pdf.ln(5)
        pdf.set_font('Arial', 'B', 12)
        pdf.set_text_color(0, 150, 200)
        pdf.cell(0, 8, 'Informacoes Tecnicas de Conectividade', 0, 1)
        pdf.set_text_color(0, 0, 0)
        
        # Table with network info
        pdf.set_font('Arial', 'B', 9)
        pdf.set_fill_color(230, 230, 230)
        pdf.cell(45, 7, 'IP Servidor', 1, 0, 'L', True)
        pdf.cell(35, 7, 'Latencia', 1, 0, 'L', True)
        pdf.cell(35, 7, 'DNS Resolve', 1, 0, 'L', True)
        pdf.cell(40, 7, 'Tempo Resposta', 1, 0, 'L', True)
        pdf.cell(35, 7, 'Servidor', 1, 1, 'L', True)
        
        pdf.set_font('Arial', '', 9)
        pdf.cell(45, 7, network_info.get('ip', 'N/A'), 1, 0, 'L')
        pdf.cell(35, 7, f"{network_info.get('latency_ms', 'N/A')} ms", 1, 0, 'L')
        pdf.cell(35, 7, f"{network_info.get('dns_time_ms', 'N/A')} ms", 1, 0, 'L')
        pdf.cell(40, 7, f"{network_info.get('response_time_ms', 'N/A')} ms", 1, 0, 'L')
        pdf.cell(35, 7, network_info.get('server', 'N/A')[:15], 1, 1, 'L')  # Truncate if too long
    
    # Category Summary
    cats = {}
    for r in results:
        c = r.get('category', 'Outros')
        cats[c] = cats.get(c, 0) + 1
    
    pdf.ln(5)
    pdf.set_font('Arial', 'B', 10)
    pdf.cell(0, 6, "Resumo por Categoria (Metodologia OWASP/Kali):", 0, 1)
    pdf.set_font('Arial', '', 10)
    for cat, count in cats.items():
        pdf.cell(0, 5, f"  - {cat}: {count} ocorrencia(s)", 0, 1)

    pdf.ln(5)

    pdf.set_font('Arial', 'B', 14)
    pdf.cell(0, 10, '2. Escopo dos Testes (Checklist)', 0, 1)
    pdf.set_font('Arial', '', 10)
    checklist_items = [
        "- Identificacao de Tecnologias e Headers",
        "- Verificacao de PHP EOL (7.2.34)",
        "- Inspecao de CSP e X-Frame-Options",
        "- Testes de Cross-Site Scripting (XSS)",
        "- Clickjacking e CORS Misconfiguration",
        "- Analise de CSRF e Cookies",
        "- Enumeracao basica de diretorios sensiveis"
    ]
    for item in checklist_items:
        pdf.cell(0, 5, item, 0, 1)
    pdf.ln(10)

    # ========== EXECUTIVE SUMMARY ==========
    try:
        from modules.executive_report_generator import generate_executive_summary_pdf
        generate_executive_summary_pdf(pdf, results, lambda x: clean_html(x) if 'clean_html' in dir() else x)
    except:
        pass  # Continue if executive summary fails

    # Findings
    pdf.set_font('Arial', 'B', 14)
    pdf.cell(0, 10, '3. Detalhes das Vulnerabilidades Encontradas', 0, 1)
    pdf.ln(2)

    def clean_html(text):
        if not text: return "-"
        import re
        
        # Remove HTML tags
        text = text.replace('<br>', '\n').replace('<br/>', '\n')
        text = text.replace('<ul>', '\n').replace('</ul>', '')
        text = text.replace('<li>', '- ').replace('</li>', '\n')
        text = re.sub('<[^<]+?>', '', text)
        
        # Remove emojis and special Unicode characters
        # Keep only ASCII + extended Latin-1 characters
        text = re.sub(r'[^\x00-\xFF]', '', text)
        
        # Ensure latin-1 compatibility for FPDF
        return text.encode('latin-1', 'replace').decode('latin-1').strip()

    for res in results:
        # Define Color based on Severity/Status
        status = res.get('status', 'Info')
        severity = res.get('severity', 'Info')
        
        # Color coding title
        if 'Critical' in severity or 'Critical' in status or status == 'Vulnerable':
            pdf.set_text_color(220, 53, 69) # Red
        elif 'High' in severity:
            pdf.set_text_color(230, 0, 0) # High Red
        elif 'Medium' in severity or status == 'Warning':
            pdf.set_text_color(255, 140, 0) # Orange
        elif 'Low' in severity:
            pdf.set_text_color(255, 193, 7) # Yellow
        else: # Safe/Info
            pdf.set_text_color(40, 167, 69) # Green

        pdf.set_font('Arial', 'B', 12)
        # Clean title to remove emojis
        vuln_title = clean_html(res.get('vulnerability', 'Vulnerabilidade'))
        pdf.cell(0, 8, f"[{status.upper()}] {vuln_title}", 0, 1)

        # Reset color for details
        pdf.set_text_color(0, 0, 0)
        pdf.set_font('Arial', 'B', 10)
        pdf.cell(25, 6, "Severidade:", 0, 0)
        pdf.set_font('Arial', '', 10)
        pdf.cell(0, 6, clean_html(severity), 0, 1)

        pdf.set_font('Arial', 'B', 10)
        pdf.cell(25, 6, "Categoria:", 0, 0)
        pdf.set_font('Arial', '', 10)
        pdf.cell(0, 6, clean_html(res.get('category', '-')), 0, 1)

        pdf.set_font('Arial', 'B', 10)
        pdf.cell(25, 6, "Detalhes:", 0, 0)
        pdf.set_font('Arial', '', 10)
        pdf.multi_cell(0, 6, clean_html(res['details']))
        
        # Add Risk
        if res.get('risk') and res['risk'] != '-':
             pdf.set_font('Arial', 'B', 10)
             pdf.cell(25, 6, "Risco:", 0, 0)
             pdf.set_font('Arial', '', 10)
             pdf.multi_cell(0, 6, clean_html(res['risk']))

        # Add Manual Test
        if res.get('manual_test') and res['manual_test'] != '-':
             pdf.set_font('Arial', 'B', 10)
             pdf.cell(25, 6, "Teste Manual:", 0, 1) # Force new line for command block
             pdf.set_font('Courier', '', 9)
             pdf.set_fill_color(240, 240, 240)
             pdf.multi_cell(0, 5, clean_html(res['manual_test']), 1, 'L', True)
             pdf.set_font('Arial', '', 10) # Reset font

        pdf.ln(5)
        
        # Append Full Checklist Table
    # Note: The original instruction provided HTML content for a table.
    # FPDF does not directly render HTML. To include a table, it must be
    # drawn using FPDF's cell/multi_cell methods.
    # The following code attempts to replicate the *structure* of the requested
    # HTML table using FPDF commands, as direct HTML insertion is not supported
    # by the FPDF library used here.

    pdf.add_page() # Start a new page for the checklist
    pdf.set_font('Arial', 'B', 14)
    pdf.set_text_color(100, 181, 246) # Light blue for title
    pdf.cell(0, 10, 'CHECKLIST COMPLETO DE VERIFICACAO', 0, 1, 'L')
    pdf.set_text_color(0, 0, 0) # Reset text color
    pdf.ln(5)

    # Table Header
    pdf.set_fill_color(51, 51, 51) # Dark grey for header background
    pdf.set_text_color(255, 255, 255) # White text for header
    pdf.set_font('Arial', 'B', 10)
    pdf.cell(25, 8, 'Status', 1, 0, 'C', True)
    pdf.cell(90, 8, 'Check / Vulnerabilidade', 1, 0, 'C', True)
    pdf.cell(40, 8, 'Categoria', 1, 0, 'C', True)
    pdf.cell(35, 8, 'Severidade', 1, 1, 'C', True) # 1 for new line

    # Sort results for the report using the same logic as app.py (Failures First)
    def get_sort_key(res):
        status_priority = 0 if res.get('status') not in ['Safe', 'Info'] else 1
        
        severity_map = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
        sev_str = res.get('severity', 'Info')
        sev_priority = 99
        for k, v in severity_map.items():
            if k in sev_str:
                sev_priority = v
                break
        return (status_priority, sev_priority)

    sorted_results = sorted(results, key=get_sort_key)

    pdf.set_font('Arial', '', 9)
    for res in sorted_results:
        status_color_rgb = (40, 167, 69) # Green
        status_text = "PASSOU"
        if res.get('status') not in ['Safe', 'Info']:
            status_color_rgb = (220, 53, 69) # Red
            status_text = "FALHOU"
        
        row_bg_rgb = (26, 26, 26) # Darker grey for row background
        text_color_rgb = (221, 221, 221) # Light grey text

        pdf.set_fill_color(*row_bg_rgb)
        pdf.set_text_color(*status_color_rgb) # Apply status color for the status cell
        pdf.cell(25, 7, status_text, 1, 0, 'C', True)

        pdf.set_text_color(*text_color_rgb) # Reset text color for other cells
        pdf.cell(90, 7, clean_html(res.get('vulnerability', '-'))[:45], 1, 0, 'L', True)
        pdf.cell(40, 7, clean_html(res.get('category', '-'))[:20], 1, 0, 'L', True)
        
        # Severity cell with background
        pdf.set_fill_color(68, 68, 68) # Darker grey for severity background
        pdf.set_text_color(221, 221, 221) # Light grey text
        pdf.cell(35, 7, clean_html(res.get('severity', 'Info')), 1, 1, 'C', True) # 1 for new line

    pdf.ln(5) # Add some space after the table

    # Developer Signature
    pdf.set_y(-30)  # Position 30mm from bottom
    pdf.set_font('Arial', 'I', 8)
    pdf.set_text_color(128, 128, 128)
    pdf.cell(0, 10, 'Desenvolvido por Maykon Silva', 0, 0, 'C')

    try:
        pdf.output(output_path)

        return output_path
    except Exception as e:
        print(f"Error generating PDF: {e}")
        return None

def generate_word_report(results, target_url, output_path, network_info=None):
    from modules.docx_reporter import generate_docx_report
    return generate_docx_report(results, target_url, output_path, network_info)

