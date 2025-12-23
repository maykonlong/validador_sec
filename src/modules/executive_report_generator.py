"""
Executive Report Generator
Generates executive summary with Risk Score, Compliance, and Attack Chains
"""

def generate_executive_summary_pdf(pdf, results, clean_html_func):
    """
    Adds executive summary section to PDF with all advanced modules
    
    Args:
        pdf: FPDF instance
        results: List of scan findings
        clean_html_func: Function to clean HTML from text
    """
    try:
        from modules.risk_calculator import RiskCalculator
        from modules.compliance_mapper import ComplianceMapper  
        from modules.vulnerability_chainer import VulnerabilityChainer
        
        if not results or len(results) == 0:
            return
        
        # ========== 1. RISK SCORE SECTION ==========
        risk_calc = RiskCalculator()
        risk_report = risk_calc.generate_risk_report(results)
        
        pdf.add_page()
        pdf.set_font('Arial', 'B', 16)
        pdf.set_text_color(200, 0, 0)
        pdf.cell(0, 10, 'RESUMO EXECUTIVO', 0, 1, 'C')
        pdf.set_text_color(0, 0, 0)
        pdf.ln(5)
        
        # Risk Score Box
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 8, f"Score de Risco: {risk_report['overall_risk_score']:.1f}/100", 0, 1)
        pdf.set_font('Arial', '', 12)
        pdf.cell(0, 7, f"Classificacao: {risk_report['risk_grade']} - {risk_report['risk_level']}", 0, 1)
        pdf.ln(3)
        
        # Executive Summary Text
        pdf.set_font('Arial', 'B', 11)
        pdf.cell(0, 6, 'Sumario:', 0, 1)
        pdf.set_font('Arial', '', 10)
        pdf.multi_cell(0, 5, risk_report['executive_summary'])
        pdf.ln(5)
        
        # Severity Breakdown
        pdf.set_font('Arial', 'B', 11)
        pdf.cell(0, 6, 'Distribuicao por Severidade:', 0, 1)
        pdf.set_font('Arial', '', 10)
        for sev, count in risk_report['severity_breakdown'].items():
            pdf.cell(0, 5, f"  {sev}: {count} findings", 0, 1)
        pdf.ln(3)
        
        # Top 5 Critical Risks
        if risk_report['top_critical_risks']:
            pdf.set_font('Arial', 'B', 11)
            pdf.cell(0, 6, 'Top 5 Riscos Criticos:', 0, 1)
            pdf.set_font('Arial', '', 9)
            for i, risk in enumerate(risk_report['top_critical_risks'][:5], 1):
                vuln_name = clean_html_func(risk['vulnerability'])[:65]
                pdf.cell(0, 5, f"  {i}. [{risk['severity']}] {vuln_name}", 0, 1)
        
        pdf.ln(8)
        
        # ========== 2. COMPLIANCE SECTION ==========
        compliance_mapper = ComplianceMapper()
        compliance_report = compliance_mapper.generate_compliance_report(results)
        
        if compliance_report['total_violations'] > 0:
            pdf.set_font('Arial', 'B', 13)
            pdf.set_text_color(0, 100, 200)
            pdf.cell(0, 8, 'COMPLIANCE OVERVIEW', 0, 1)
            pdf.set_text_color(0, 0, 0)
            pdf.ln(2)
            
            pdf.set_font('Arial', '', 10)
            pdf.cell(0, 6, f"Total de Violacoes: {compliance_report['total_violations']}", 0, 1)
            pdf.ln(2)
            
            # Framework compliance table
            pdf.set_font('Arial', 'B', 9)
            pdf.cell(60, 7, 'Framework', 1, 0, 'L')
            pdf.cell(30, 7, 'Violations', 1, 0, 'C')
            pdf.cell(90, 7, 'Status', 1, 1, 'L')
            
            pdf.set_font('Arial', '', 9)
            for framework, data in list(compliance_report['by_framework'].items())[:6]:
                if data['violations'] > 0:
                    pdf.cell(60, 6, framework, 1, 0, 'L')
                    pdf.cell(30, 6, str(data['violations']), 1, 0, 'C')
                    pdf.cell(90, 6, data['status'][:40], 1, 1, 'L')
            
            pdf.ln(8)
        
        # ========== 3. ATTACK CHAINS SECTION ==========
        chainer = VulnerabilityChainer()
        chains = chainer.detect_chains(results)
        
        if chains:
            pdf.set_font('Arial', 'B', 13)
            pdf.set_text_color(200, 0, 100)
            pdf.cell(0, 8, 'CADEIAS DE ATAQUE DETECTADAS', 0, 1)
            pdf.set_text_color(0, 0, 0)
            pdf.ln(2)
            
            pdf.set_font('Arial', '', 9)
            for i, chain in enumerate(chains[:5], 1):  # Top 5 chains
                pdf.set_font('Arial', 'B', 10)
                pdf.cell(0, 6, f"{i}. {chain['name']}", 0, 1)
                
                pdf.set_font('Arial', '', 9)
                pdf.cell(0, 5, f"   Severidade Combinada: {chain['combined_severity']} (CVSS: {chain['cvss_score']})", 0, 1)
                
                impact_clean = clean_html_func(chain['impact'])[:120]
                pdf.multi_cell(0, 4, f"   Impacto: {impact_clean}")
                
                # List involved vulnerabilities
                pdf.set_font('Arial', 'I', 8)
                vuln_names = ', '.join([clean_html_func(v['vulnerability'])[:30] for v in chain['findings'][:3]])
                pdf.cell(0, 4, f"   Envolve: {vuln_names}", 0, 1)
                pdf.ln(2)
            
            pdf.ln(5)
        
        # ========== 4. REMEDIATION PRIORITY ==========
        if 'remediation_priority' in risk_report:
            pdf.set_font('Arial', 'B', 13)
            pdf.cell(0, 8, 'PRIORIDADE DE REMEDIACAO', 0, 1)
            pdf.ln(2)
            
            pdf.set_font('Arial', '', 9)
            for priority, count in risk_report['remediation_priority'].items():
                if count > 0:
                    pdf.cell(0, 5, f"  {priority}: {count} findings", 0, 1)
        
        return True
        
    except Exception as e:
        # If executive summary fails, don't break the report
        print(f"Warning: Executive summary generation failed: {e}")
        return False


def generate_executive_summary_html(results):
    """
    Generates HTML executive summary for web reports
    
    Args:
        results: List of scan findings
    
    Returns:
        HTML string with executive summary
    """
    try:
        from modules.risk_calculator import RiskCalculator
        from modules.compliance_mapper import ComplianceMapper  
        from modules.vulnerability_chainer import VulnerabilityChainer
        
        if not results:
            return "<p>No findings to report.</p>"
        
        risk_calc = RiskCalculator()
        risk_report = risk_calc.generate_risk_report(results)
        
        html = f"""
        <div class="executive-summary">
            <h2>📊 RESUMO EXECUTIVO</h2>
            
            <div class="risk-score-box">
                <h3>Score de Risco: {risk_report['overall_risk_score']:.1f}/100</h3>
                <p>Classificação: {risk_report['risk_grade']} - {risk_report['risk_level']}</p>
            </div>
            
            <div class="summary-text">
                <h4>Sumário</h4>
                <p>{risk_report['executive_summary']}</p>
            </div>
            
            <div class="severity-breakdown">
                <h4>Distribuição por Severidade</h4>
                <ul>
        """
        
        for sev, count in risk_report['severity_breakdown'].items():
            html += f"<li>{sev}: {count} findings</li>"
        
        html += "</ul></div>"
        
        # Add compliance if available
        compliance_mapper = ComplianceMapper()
        compliance_report = compliance_mapper.generate_compliance_report(results)
        
        if compliance_report['total_violations'] > 0:
            html += f"""
            <div class="compliance-section">
                <h4>Compliance Overview</h4>
                <p>Total Violations: {compliance_report['total_violations']}</p>
                <ul>
            """
            for framework, data in list(compliance_report['by_framework'].items())[:5]:
                if data['violations'] > 0:
                    html += f"<li>{framework}: {data['violations']} violations - {data['status']}</li>"
            html += "</ul></div>"
        
        # Add chains if available
        chainer = VulnerabilityChainer()
        chains = chainer.detect_chains(results)
        
        if chains:
            html += """
            <div class="attack-chains">
                <h4>Cadeias de Ataque Detectadas</h4>
                <ul>
            """
            for chain in chains[:3]:
                html += f"""
                <li>
                    <strong>{chain['name']}</strong> 
                    (Severidade: {chain['combined_severity']}, CVSS: {chain['cvss_score']})<br>
                    <em>{chain['impact'][:100]}...</em>
                </li>
                """
            html += "</ul></div>"
        
        html += "</div>"
        
        return html
        
    except Exception as e:
        return f"<p>Error generating executive summary: {e}</p>"
