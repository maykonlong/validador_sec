# 🎯 TAREFAS DE UI - INSTRUÇÕES COMPLETAS

## ✅ **TAREFA #1: Progress Bar + Logs em Tempo Real**
**Status:** Instruções criadas (ver TASK1_PROGRESS_BAR_INSTRUCTIONS.md)

---

## ✅ **TAREFA #2: Checkboxes para Novos Módulos**

### 📍 Localização: `src/templates/index.html` - Linha ~850

### 🔧 O Que Fazer:
Localize esta seção (após o checkbox RED TEAM):
```html
<label class="option-item">
    <input type="checkbox" name="allow_invasive" value="on">
    <span style="color: var(--accent-red);">RED TEAM</span>
</label>
```

### ➕ Adicione LOGO APÓS (antes de fechar `</div>`):
```html
<!-- NEW MODULES - Adicione aqui -->
<label class="option-item" title="🔍 OWASP API Security Top 10" style="border-left: 2px solid var(--accent-cyan);">
    <input type="checkbox" name="api_security" value="on" checked>
    <span style="color: var(--accent-cyan);">API SECURITY</span>
</label>

<label class="option-item" title="🌐 CVE enrichment + exploit data">
    <input type="checkbox" name="threat_intel" value="on" checked>
    <span style="color: var(--accent-purple);">THREAT INTEL</span>
</label>

<label class="option-item" title="📚 Fix guides com código">
    <input type="checkbox" name="remediation_guides" value="on" checked>
    <span style="color: var(--accent-green);">FIX GUIDES</span>
</label>
```

---

## ✅ **TAREFA #3: Área de Findings em Tempo Real**

### 📍 Localização: `src/templates/index.html` - Após o formulário

### ➕ Adicione Antes da Seção de Resultados:
```html
<!-- FINDINGS PREVIEW - Adicione após progress-section -->
<div id="findings-preview" style="display: none; margin-top: 20px;">
    <div style="background: rgba(16, 20, 32, 0.8); border: 1px solid rgba(0, 243, 255, 0.3); border-radius: 8px; padding: 20px;">
        <h3 style="color: #00f3ff; font-family: 'Orbitron'; margin-bottom: 15px;">🔍 ÚLTIMOS FINDINGS:</h3>
        
        <!-- Findings Counter -->
        <div style="display: flex; gap: 20px; margin-bottom: 20px; flex-wrap: wrap;">
            <div style="text-align: center; padding: 10px 20px; background: rgba(239, 68, 68, 0.1); border: 1px solid #ef4444; border-radius: 4px;">
                <div style="font-size: 1.5rem; font-weight: bold; color: #ef4444;">
                    <span id="live-critical-count">0</span>
                </div>
                <div style="font-size: 0.8rem; color: #94a3b8;">Critical</div>
            </div>
            <div style="text-align: center; padding: 10px 20px; background: rgba(245, 158, 11, 0.1); border: 1px solid #f59e0b; border-radius: 4px;">
                <div style="font-size: 1.5rem; font-weight: bold; color: #f59e0b;">
                    <span id="live-high-count">0</span>
                </div>
                <div style="font-size: 0.8rem; color: #94a3b8;">High</div>
            </div>
            <div style="text-align: center; padding: 10px 20px; background: rgba(251, 191, 36, 0.1); border: 1px solid #fbbf24; border-radius: 4px;">
                <div style="font-size: 1.5rem; font-weight: bold; color: #fbbf24;">
                    <span id="live-medium-count">0</span>
                </div>
                <div style="font-size: 0.8rem; color: #94a3b8;">Medium</div>
            </div>
            <div style="text-align: center; padding: 10px 20px; background: rgba(16, 185, 129, 0.1); border: 1px solid #10b981; border-radius: 4px;">
                <div style="font-size: 1.5rem; font-weight: bold; color: #10b981;">
                    <span id="live-safe-count">0</span>
                </div>
                <div style="font-size: 0.8rem; color: #94a3b8;">Safe</div>
            </div>
        </div>

        <!-- Live Findings List -->
        <div id="live-findings-list" style="max-height: 300px; overflow-y: auto;">
            <div style="color: #94a3b8; text-align: center; padding: 20px;">
                Aguardando findings...
            </div>
        </div>
    </div>
</div>

<script>
// JavaScript para Live Findings
function addLiveFinding(finding) {
    const list = document.getElementById('live-findings-list');
    if (list.children[0].textContent.includes('Aguardando')) {
        list.innerHTML = '';
    }
    
    const severityColors = {
        'Critical': '#ef4444',
        'High': '#f59e0b',
        'Medium': '#fbbf24',
        'Low': '#10b981',
        'Info': '#00f3ff'
    };
    
    const entry = document.createElement('div');
    entry.style.cssText = 'padding: 12px; margin-bottom: 8px; background: rgba(0,0,0,0.3); border-left: 3px solid ' + (severityColors[finding.severity] || '#00f3ff') + '; border-radius: 4px; animation: slideIn 0.3s ease;';
    
    entry.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <span style="color: #f1f5f9; font-weight: bold;">${finding.vulnerability}</span>
            <span style="background: ${severityColors[finding.severity]}; color: #000; padding: 2px 8px; border-radius: 3px; font-size: 0.7rem; font-weight: bold;">${finding.severity}</span>
        </div>
        <div style="color: #94a3b8; font-size: 0.85rem; margin-top: 5px;">${finding.details.substring(0, 100)}...</div>
    `;
    
    list.insertBefore(entry, list.firstChild);
    
    // Update counters
    updateLiveCounters(finding.severity);
    
    // Limit to 10 findings
    while (list.children.length > 10) {
        list.removeChild(list.lastChild);
    }
}

function updateLiveCounters(severity) {
    const counter = document.getElementById(`live-${severity.toLowerCase()}-count`);
    if (counter) {
        counter.textContent = parseInt(counter.textContent) + 1;
    }
}

// CSS Animation
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            opacity: 0;
            transform: translateX(-20px);
        }
        to {
            opacity: 1;
            transform: translateX(0);
        }
    }
`;
document.head.appendChild(style);
</script>
```

---

## ✅ **TAREFA #4: Botões de Export**

### 📍 Localização: Após a seção de resultados

### ➕ Adicione Export Bar:
```html
<!-- EXPORT BUTTONS - Adicione após findings-preview -->
<div id="export-bar" style="display: none; margin-top: 20px;">
    <div style="background: rgba(16, 20, 32, 0.8); border: 1px solid rgba(0, 243, 255, 0.3); border-radius: 8px; padding: 20px;">
        <h3 style="color: #00f3ff; font-family: 'Orbitron'; margin-bottom: 15px;">📥 EXPORTAR RESULTADOS:</h3>
        
        <div style="display: flex; gap: 15px; flex-wrap: wrap;">
            <button onclick="exportPDF()" style="flex: 1; min-width: 150px; padding: 12px 20px; background: linear-gradient(135deg, #ef4444, #dc2626); border: none; color: white; font-family: 'Orbitron'; font-weight: bold; border-radius: 4px; cursor: pointer; transition: all 0.3s;">
                📄 EXPORT PDF
            </button>
            
            <button onclick="exportJSON()" style="flex: 1; min-width: 150px; padding: 12px 20px; background: linear-gradient(135deg, #00f3ff, #0891b2); border: none; color: #000; font-family: 'Orbitron'; font-weight: bold; border-radius: 4px; cursor: pointer; transition: all 0.3s;">
                📋 COPY JSON
            </button>
            
            <button onclick="exportHTML()" style="flex: 1; min-width: 150px; padding: 12px 20px; background: linear-gradient(135deg, #10b981, #059669); border: none; color: white; font-family: 'Orbitron'; font-weight: bold; border-radius: 4px; cursor: pointer; transition: all 0.3s;">
                🌐 EXPORT HTML
            </button>
            
            <button onclick="shareResults()" style="flex: 1; min-width: 150px; padding: 12px 20px; background: linear-gradient(135deg, #8b5cf6, #7c3aed); border: none; color: white; font-family: 'Orbitron'; font-weight: bold; border-radius: 4px; cursor: pointer; transition: all 0.3s;">
                🔗 SHARE LINK
            </button>
        </div>
    </div>
</div>

<script>
function exportPDF() {
    window.open('/download/pdf', '_blank');
}

function exportJSON() {
    fetch('/api/results/json')
        .then(r => r.json())
        .then(data => {
            navigator.clipboard.writeText(JSON.stringify(data, null, 2));
            alert('✅ JSON copiado para clipboard!');
        });
}

function exportHTML() {
    window.open('/download/html', '_blank');
}

function shareResults() {
    const shareUrl = window.location.origin + '/share/' + scanId;
    navigator.clipboard.writeText(shareUrl);
    alert('✅ Link copiado: ' + shareUrl);
}
</script>
```

---

## 📊 **RESUMO DAS 4 TAREFAS:**

| Task | Arquivo | Linha | Status |
|------|---------|-------|--------|
| #1 Progress Bar | index.html | ~816 | 📝 Instruções prontas |
| #2 Checkboxes   | index.html | ~850 | ✅ Código pronto acima |
| #3 Live Findings | index.html | Após form | ✅ Código pronto acima |
| #4 Export Buttons | index.html | Final | ✅ Código pronto acima |

---

## 🚀 **APLICAR TUDO DE UMA VEZ:**

1. Abra `src/templates/index.html`
2. Localize linha ~850 (após RED TEAM checkbox)
3. Cole os 3 checkboxes da Task #2
4. Localize linha ~900 (após formulário)
5. Cole a Task #3 (Live Findings)
6. Logo após, cole a Task #4 (Export Buttons)
7. Salve e teste!

**Seu scanner ficará PROFISSIONAL!** 🔥
