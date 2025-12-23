# INSTRUÇÕES COMPLETAS: UI Updates + Card de Subdomínios

## 🎯 **PARTE 1: Adicionar Card de Subdomínios Fixo**

### 📍 Localização: `src/templates/index.html` - Logo após `</form>` (linha ~855)

### ➕ Adicione ESTE CÓDIGO:

```html
        </form>
        
        <!-- ========== CARD FIXO: SUBDOMÍNIOS ========== -->
        <div id="subdomains-card" style="display: none; margin-top: 30px;">
            <div class="subdomain-card-container" style="background: linear-gradient(135deg, rgba(139, 92, 246, 0.1), rgba(0, 243, 255, 0.1)); border: 2px solid var(--accent-purple); border-radius: 12px; padding: 25px; position: relative; overflow: hidden;">
                
                <!-- Animated background -->
                <div style="position: absolute; top: 0; left: 0; width: 100%; height: 100%; opacity: 0.03; background: repeating-linear-gradient(45deg, transparent, transparent 10px, var(--accent-cyan) 10px, var(--accent-cyan) 20px);"></div>
                
                <div style="position: relative; z-index: 1;">
                    <!-- Header -->
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                        <div>
                            <h2 style="font-family: 'Orbitron', sans-serif; color: var(--accent-purple); font-size: 1.5rem; margin: 0; display: flex; align-items: center; gap: 10px;">
                                <span style="font-size: 1.8rem;">🌐</span>
                                SUBDOMÍNIOS DESCOBERTOS
                            </h2>
                            <p style="color: var(--text-muted); font-size: 0.85rem; margin: 5px 0 0 0;">
                                Enumeração via Certificate Transparency
                            </p>
                        </div>
                        <div id="subdomain-count-badge" style="background: var(--accent-purple); color: #000; padding: 8px 20px; border-radius: 20px; font-family: 'Orbitron'; font-weight: bold; font-size: 1.2rem; box-shadow: 0 0 20px rgba(139, 92, 246, 0.5);">
                            0
                        </div>
                    </div>

                    <!-- Stats Row -->
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px;">
                        <div style="background: rgba(0, 0, 0, 0.3); padding: 15px; border-radius: 8px; border-left: 3px solid var(--accent-cyan);">
                            <div style="font-size: 0.75rem; color: var(--text-muted); margin-bottom: 5px;">MÉTODO</div>
                            <div style="color: var(--accent-cyan); font-weight: bold;">crt.sh API</div>
                        </div>
                        <div style="background: rgba(0, 0, 0, 0.3); padding: 15px; border-radius: 8px; border-left: 3px solid var(--accent-green);">
                            <div style="font-size: 0.75rem; color: var(--text-muted); margin-bottom: 5px;">TIPO</div>
                            <div style="color: var(--accent-green); font-weight: bold;">Passivo / Sem Impacto</div>
                        </div>
                        <div style="background: rgba(0, 0, 0, 0.3); padding: 15px; border-radius: 8px; border-left: 3px solid var(--accent-orange);">
                            <div style="font-size: 0.75rem; color: var(--text-muted); margin-bottom: 5px;">STATUS</div>
                            <div style="color: var(--accent-orange); font-weight: bold;" id="subdomain-status">Buscando...</div>
                        </div>
                    </div>

                    <!-- Subdomains List -->
                    <div style="background: rgba(0, 0, 0, 0.4); border-radius: 8px; padding: 20px; max-height: 400px; overflow-y: auto; border: 1px solid rgba(255, 255, 255, 0.1);">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                            <h3 style="font-family: 'Orbitron'; color: var(--accent-cyan); font-size: 0.9rem; margin: 0;">LISTA DE SUBDOMÍNIOS:</h3>
                            <button onclick="copySubdomains()" style="background: rgba(0, 243, 255, 0.2); border: 1px solid var(--accent-cyan); color: var(--accent-cyan); padding: 6px 15px; border-radius: 4px; cursor: pointer; font-family: 'Roboto Mono'; font-size: 0.75rem; transition: all 0.3s;">
                                📋 COPIAR LISTA
                            </button>
                        </div>
                        
                        <div id="subdomains-list" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 10px;">
                            <div style="color: var(--text-muted); text-align: center; padding: 40px; grid-column: 1 / -1;">
                                <div style="font-size: 3rem; margin-bottom: 10px;">🔍</div>
                                <div>Aguardando scan...</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <!-- ========== FIM DO CARD DE SUBDOMÍNIOS ========== -->

        <div id="results-section" style="margin-top: 40px;">
```

---

## 🎯 **PARTE 2: JavaScript para Subdomínios**

### 📍 Localização: No final do `<script>` principal (antes de `</script>`)

### ➕ Adicione:

```javascript
// ========== SUBDOMAINS CARD FUNCTIONS ==========
let discoveredSubdomains = [];

function displaySubdomains(subdomains) {
    if (!subdomains || subdomains.length === 0) return;
    
    discoveredSubdomains = subdomains;
    
    // Show card
    document.getElementById('subdomains-card').style.display = 'block';
    
    // Update count
    document.getElementById('subdomain-count-badge').textContent = subdomains.length;
    document.getElementById('subdomain-status').textContent = '✅ Completo';
    document.getElementById('subdomain-status').style.color = 'var(--accent-green)';
    
    // Render list
    const listContainer = document.getElementById('subdomains-list');
    listContainer.innerHTML = '';
    
    subdomains.forEach((subdomain, index) => {
        const item = document.createElement('div');
        item.style.cssText = `
            background: rgba(139, 92, 246, 0.1);
            border: 1px solid rgba(139, 92, 246, 0.3);
            border-radius: 6px;
            padding: 12px;
            font-family: 'Roboto Mono';
            font-size: 0.85rem;
            color: var(--text-main);
            transition: all 0.3s;
            cursor: pointer;
            animation: slideIn 0.3s ease ${index * 0.05}s both;
        `;
        
        item.innerHTML = `
            <div style="display: flex; align-items: center; gap: 8px;">
                <span style="color: var(--accent-purple); font-weight: bold; font-size: 0.7rem;">#${index + 1}</span>
                <code style="color: var(--accent-cyan); word-break: break-all;">${subdomain}</code>
            </div>
        `;
        
        item.onmouseover = () => {
            item.style.background = 'rgba(139, 92, 246, 0.2)';
            item.style.borderColor = 'var(--accent-purple)';
            item.style.transform = 'translateX(5px)';
        };
        item.onmouseout = () => {
            item.style.background = 'rgba(139, 92, 246, 0.1)';
            item.style.borderColor = 'rgba(139, 92, 246, 0.3)';
            item.style.transform = 'translateX(0)';
        };
        item.onclick = () => {
            navigator.clipboard.writeText(subdomain);
            showToast(`✅ Copiado: ${subdomain}`);
        };
        
        listContainer.appendChild(item);
    });
}

function copySubdomains() {
    const text = discoveredSubdomains.join('\n');
    navigator.clipboard.writeText(text);
    showToast(`✅ ${discoveredSubdomains.length} subdomínios copiados!`);
}

function showToast(message) {
    const toast = document.createElement('div');
    toast.textContent = message;
    toast.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        background: var(--accent-green);
        color: #000;
        padding: 15px 25px;
        border-radius: 8px;
        font-family: 'Orbitron';
        font-weight: bold;
        box-shadow: 0 5px 20px rgba(16, 185, 129, 0.5);
        z-index: 10000;
        animation: slideInRight 0.3s ease;
    `;
    document.body.appendChild(toast);
    setTimeout(() => {
        toast.style.animation = 'slideOutRight 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Add slide animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            opacity: 0;
            transform: translateY(20px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    @keyframes slideInRight {
        from { transform: translateX(100%); }
        to { transform: translateX(0); }
    }
    @keyframes slideOutRight {
        from { transform: translateX(0); }
        to { transform: translateX(100%); }
    }
`;
document.head.appendChild(style);
</script>
```

---

## 🎯 **PARTE 3: Integrar com Resultados do Scan**

### 📍 Localização: Onde os resultados são processados (linha ~1600-1700)

### 🔧 Modifique a função que processa os resultados:

Procure por algo como:
```javascript
// Process results
results.forEach(result => {
    // render card
});
```

E ANTES do loop, adicione:
```javascript
// Extract and display subdomains if present
const subdomainFinding = results.find(r => 
    r.vulnerability && r.vulnerability.includes('Subdomínio')
);

if (subdomainFinding && subdomainFinding.details) {
    // Extract subdomains from details
    const match = subdomainFinding.details.match(/• <code>(.*?)<\/code>/g);
    if (match) {
        const subs = match.map(m => m.replace(/• <code>|<\/code>/g, ''));
        displaySubdomains(subs);
    }
}
```

---

## 📊 **RESULTADO ESPERADO:**

O card vai aparecer **FIXO NO TOPO**, antes de todos os outros findings, mostrando:

✅ **Badge com total de subdomínios**  
✅ **Método de descoberta (crt.sh)**  
✅ **Lista em grid responsivo**  
✅ **Copiar individual (clique)**  
✅ **Copiar todos (botão)**  
✅ **Animações suaves**  

**Agora aplique as instruções acima!** 🚀

Quer que eu continue com mais melhorias ou está bom assim?
