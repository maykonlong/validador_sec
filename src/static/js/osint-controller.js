/**
 * OSINT Controller - Gerencia interface dinâmica de investigações
 */

class OsintController {
    constructor() {
        this.currentMission = null;
        this.investigationResults = null;

        // Form templates for each mission type
        this.formTemplates = {
            'email': this.getEmailForm.bind(this),
            'domain': this.getDomainForm.bind(this),
            'phishing': this.getPhishingForm.bind(this),
            'person': this.getPersonForm.bind(this),
            'phone': this.getPhoneForm.bind(this)
        };

        // Mission titles
        this.missionTitles = {
            'email': '📧 Investigação de E-mail',
            'domain': '🌐 Auditoria de Domínio',
            'phishing': '🎣 Detecção de Phishing',
            'person': '👤 Investigação de Pessoa',
            'phone': '📱 Análise de Telefone'
        };

        this.init();
    }

    init() {
        this.attachEventListeners();
    }

    attachEventListeners() {
        // Mission cards selection
        document.querySelectorAll('.mission-card').forEach(card => {
            card.addEventListener('click', () => {
                this.selectMission(card.dataset.mission);
            });
        });

        // Back button
        document.getElementById('btn-back').addEventListener('click', () => {
            this.backToMissionSelector();
        });

        // Form submission
        // Form submission
        document.getElementById('osint-form').addEventListener('submit', (e) => {
            e.preventDefault();

            // Se for investigação de telefone
            if (this.currentMission === 'phone') {
                const phoneFinal = document.getElementById('phone-final');

                // Tenta reconstruir o número se estiver vazio (Fallback de Segurança)
                if (!phoneFinal.value) {
                    const country = document.getElementById('phone-country')?.value;
                    const ddd = document.getElementById('phone-ddd')?.value?.replace(/\D/g, '');
                    const num = document.getElementById('phone-number')?.value?.replace(/\D/g, '');
                    const international = document.getElementById('phone-international')?.value?.replace(/\D/g, '');

                    if (country === '+55' && ddd && num) {
                        phoneFinal.value = '+55 ' + ddd + ' ' + num;
                    } else if (country && international) {
                        phoneFinal.value = country + ' ' + international;
                    }
                }

                // Validação final
                if (!phoneFinal.value || phoneFinal.value.trim() === '') {
                    alert('❌ Por favor, preencha o número de telefone corretamente');
                    return false;
                }
            }

            this.executeInvestigation();
        });

        // New investigation button
        document.getElementById('btn-new-investigation').addEventListener('click', () => {
            this.backToMissionSelector();
        });

        // Download buttons
        document.getElementById('btn-download-pdf').addEventListener('click', () => {
            this.downloadReport('pdf');
        });

        document.getElementById('btn-download-json').addEventListener('click', () => {
            this.downloadReport('json');
        });
    }

    selectMission(missionType) {
        this.currentMission = missionType;

        // Hide mission selector, show investigation panel
        document.getElementById('mission-selector').style.display = 'none';
        document.getElementById('investigation-panel').classList.add('active');

        // Load mission-specific form
        this.loadMissionForm(missionType);
    }

    loadMissionForm(missionType) {
        const formTemplate = this.formTemplates[missionType];
        const dynamicFields = document.getElementById('dynamic-fields');
        const advancedFields = document.getElementById('advanced-fields');

        // Generate form fields
        const fields = formTemplate();
        dynamicFields.innerHTML = fields.main;
        advancedFields.innerHTML = fields.advanced || '';

        // Update title
        document.getElementById('mission-title').textContent = this.missionTitles[missionType];

        // Set hidden mission type
        document.getElementById('mission-type').value = missionType;
    }

    backToMissionSelector() {
        // Hide panels
        document.getElementById('investigation-panel').classList.remove('active');
        document.getElementById('results-panel').classList.remove('active');

        // Show mission selector
        document.getElementById('mission-selector').style.display = 'block';

        // Reset form
        document.getElementById('osint-form').reset();

        // Reset results
        this.investigationResults = null;
        document.getElementById('results-container').style.display = 'none';
        document.getElementById('action-buttons').style.display = 'none';
    }

    async executeInvestigation() {
        const formData = new FormData(document.getElementById('osint-form'));

        // Hide investigation panel, show results panel
        document.getElementById('investigation-panel').classList.remove('active');
        document.getElementById('results-panel').classList.add('active');

        // Show progress indicator
        document.getElementById('progress-indicator').style.display = 'block';
        document.getElementById('results-container').style.display = 'none';
        document.getElementById('action-buttons').style.display = 'none';

        try {
            const response = await fetch('/osint/execute', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            // Stream progress updates
            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let buffer = '';

            while (true) {
                const { done, value } = await reader.read();

                if (done) break;

                buffer += decoder.decode(value, { stream: true });

                // Process complete JSON objects from buffer
                const lines = buffer.split('\n');
                buffer = lines.pop() || ''; // Keep incomplete line in buffer

                for (const line of lines) {
                    if (line.trim()) {
                        try {
                            const data = JSON.parse(line);
                            this.handleProgressUpdate(data);
                        } catch (e) {
                            console.error('Error parsing JSON:', e, line);
                        }
                    }
                }
            }

        } catch (error) {
            console.error('Investigation error:', error);
            this.showError(error.message);
        }
    }

    handleProgressUpdate(data) {
        if (data.progress !== undefined) {
            // Update progress bar
            const progressBar = document.getElementById('progress-bar');
            const progressStatus = document.getElementById('progress-status');

            progressBar.style.width = data.progress + '%';
            progressStatus.textContent = data.message || 'Processando...';
        }

        if (data.done) {
            // Investigation complete, display results
            this.investigationResults = data.results;
            this.lastReportId = data.report_id; // Capture ID for PDF generation
            this.displayResults(data.results);
        }
    }

    displayResults(results) {
        // Hide progress, show results
        document.getElementById('progress-indicator').style.display = 'none';
        document.getElementById('results-container').style.display = 'block';
        document.getElementById('action-buttons').style.display = 'flex';

        // Display Summary
        this.displaySummary(results.summary);

        // Display Findings
        this.displayFindings(results.findings);

        // Display Recommendations
        if (results.recommendations && results.recommendations.length > 0) {
            document.getElementById('recommendations-section').style.display = 'block';
            this.displayRecommendations(results.recommendations);
        }
    }

    displaySummary(summary) {
        const container = document.getElementById('summary-content');
        let html = '<div style="background: var(--osint-dark-lighter); padding: 1.5rem; border-radius: 8px;">';

        for (const [key, value] of Object.entries(summary)) {
            const label = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            html += `
                <div style="margin-bottom: 0.75rem;">
                    <strong style="color: var(--osint-primary);">${label}:</strong>
                    <span style="color: var(--osint-text);">${value}</span>
                </div>
            `;
        }

        html += '</div>';
        container.innerHTML = html;
    }

    displayFindings(findings) {
        const container = document.getElementById('findings-content');
        let html = '';

        if (!findings || findings.length === 0) {
            html = '<p style="color: var(--osint-text-muted);">Nenhuma descoberta relevante.</p>';
        } else {
            findings.forEach(finding => {
                const severityClass = `severity-${finding.severity || 'info'}`;

                // Formatar dados de forma visual ao invés de JSON
                let detailsHtml = finding.description || '';

                // Se tiver dados, formatar visualmente
                if (finding.data) {
                    detailsHtml += this.formatFindingData(finding.type, finding.data);
                }

                html += `
                    <div class="finding-card ${severityClass}">
                        <h4 style="margin-bottom: 0.5rem; color: var(--osint-text);">
                            ${finding.title || 'Discovery'}
                        </h4>
                        <div style="color: var(--osint-text-muted); margin-bottom: 0.5rem;">
                            ${detailsHtml}
                        </div>
                    </div>
                `;
            });
        }

        container.innerHTML = html;
    }

    formatFindingData(type, data) {
        let html = '';

        // Formatação específica por tipo de finding
        switch (type) {
            case 'social_profiles':
            case 'manual_search':
                if (data.profiles && data.profiles.length > 0) {
                    html += `
                        <div style='margin-top: 12px; padding: 12px; background: rgba(0, 170, 255, 0.08); border-radius: 6px;'>
                            <strong style='color: var(--osint-secondary);'>🔗 Perfis Encontrados:</strong><br>
                            <div style='margin-top: 8px; display: grid; gap: 8px;'>
                    `;

                    data.profiles.forEach(profile => {
                        html += `
                            <div style='padding: 8px; background: rgba(0, 0, 0, 0.2); border-radius: 4px; border-left: 3px solid var(--osint-secondary);'>
                                <strong>${profile.network || profile.site}</strong><br>
                                <a href='${profile.url}' target='_blank' style='color: var(--osint-primary); text-decoration: none; font-size: 0.9em;'>
                                    ${profile.url} →
                                </a>
                            </div>
                        `;
                    });

                    html += `
                            </div>
                        </div>
                    `;
                }
                break;

            case 'username_analysis':
                html += `
                    <div style='margin-top: 12px; padding: 12px; background: rgba(0, 255, 157, 0.08); border-radius: 6px;'>
                        <strong style='color: var(--osint-success);'>📊 Características:</strong><br>
                        <div style='margin-top: 8px; padding-left: 10px;'>
                `;

                if (data.length !== undefined) {
                    html += `<div>📏 Comprimento: ${data.length} caracteres</div>`;
                }
                if (data.has_numbers !== undefined) {
                    html += `<div>🔢 Contém números: ${data.has_numbers ? 'Sim' : 'Não'}</div>`;
                }
                if (data.has_special !== undefined) {
                    html += `<div>✨ Caracteres especiais: ${data.has_special ? 'Sim' : 'Não'}</div>`;
                }

                if (data.common_patterns && data.common_patterns.length > 0) {
                    html += `
                        <div style='margin-top: 8px;'>
                            <strong>⚠️ Padrões detectados:</strong><br>
                            <ul style='margin: 5px 0; padding-left: 20px;'>
                    `;
                    data.common_patterns.forEach(pattern => {
                        html += `<li style='color: var(--osint-warning);'>${pattern}</li>`;
                    });
                    html += `</ul></div>`;
                }

                if (data.username) {
                    html += `
                        <div style='margin-top: 15px; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 10px;'>
                            <div style='color: var(--osint-text-muted); font-size: 0.9em; margin-bottom: 8px;'>⚠️ Redes com proteção Anti-Bot (Verificar Manualmente):</div>
                            <div style='display: flex; gap: 8px; flex-wrap: wrap;'>
                                <a href='https://instagram.com/${data.username}' target='_blank' style='background: linear-gradient(45deg, #f09433, #e6683c, #dc2743, #cc2366, #bc1888); color: white; padding: 6px 12px; border-radius: 4px; text-decoration: none; font-size: 0.85em; font-weight:bold;'>Instagram ↗</a>
                                <a href='https://www.threads.net/@${data.username}' target='_blank' style='background: #111; color: white; border: 1px solid #333; padding: 6px 12px; border-radius: 4px; text-decoration: none; font-size: 0.85em; font-weight:bold;'>Threads ↗</a>
                                <a href='https://tiktok.com/@${data.username}' target='_blank' style='background: #111; color: white; border: 1px solid #333; padding: 6px 12px; border-radius: 4px; text-decoration: none; font-size: 0.85em; font-weight:bold;'>TikTok ↗</a>
                            </div>
                        </div>
                    `;
                }

                html += `
                        </div>
                    </div>
                `;
                break;

            case 'sherlock_scan':
            case 'maigret_scan':
                if (data.profiles && data.profiles.length > 0) {
                    const tool = type === 'sherlock_scan' ? 'Sherlock' : 'Maigret';
                    html += `
                        <div style='margin-top: 12px; padding: 12px; background: rgba(0, 255, 136, 0.08); border-radius: 6px; border: 1px solid var(--osint-success);'>
                            <strong style='color: var(--osint-success);'>✅ ${tool} - ${data.profiles_found} perfil(is) confirmado(s)</strong><br>
                            <div style='margin-top: 10px; max-height: 300px; overflow-y: auto; display: grid; gap: 6px;'>
                    `;

                    data.profiles.forEach(profile => {
                        html += `
                            <div style='padding: 6px 10px; background: rgba(0, 0, 0, 0.3); border-radius: 4px; border-left: 2px solid var(--osint-success); display: flex; justify-content: space-between; align-items: center;'>
                                <span style='font-weight: 600;'>${profile.site}</span>
                                <a href='${profile.url}' target='_blank' style='color: var(--osint-primary); text-decoration: none; font-size: 0.85em;'>
                                    Abrir →
                                </a>
                            </div>
                        `;
                    });

                    html += `
                            </div>
                        </div>
                    `;
                } else if (data.error) {
                    html += `
                        <div style='margin-top: 12px; padding: 12px; background: rgba(255, 160, 0, 0.08); border-radius: 6px;'>
                            <strong style='color: var(--osint-warning);'>⚠️ Erro:</strong> ${data.error}
                        </div>
                    `;
                }
                break;


            case 'phonenumbers_analysis':
                // Análise completa com phonenumbers
                if (data.is_valid !== undefined) {
                    const validIcon = data.is_valid ? '✅' : '⚠️';
                    const validColor = data.is_valid ? 'var(--osint-success)' : 'var(--osint-warning)';

                    html += `
                        <div style='margin-top: 12px; padding: 14px; background: rgba(0, 243, 255, 0.08); border-radius: 6px; border: 1px solid var(--osint-secondary);'>
                            <strong style='color: ${validColor};'>${validIcon} Análise Completa</strong><br>
                            <div style='margin-top: 10px; padding-left: 10px; display: grid; gap: 6px;'>
                                <div>📞 <strong>Tipo:</strong> ${data.type}</div>
                                <div>🌐 <strong>País:</strong> ${data.region} (${data.country_code})</div>
                                <div>📍 <strong>Localização:</strong> ${data.location}</div>
                                ${data.operator ? `<div>📡 <strong>Operadora:</strong> <span style='color: var(--osint-primary);'>${data.operator}</span></div>` : ''}
                                ${data.is_possible ? `<div>✓ <strong>Número possível:</strong> Sim</div>` : ''}
                            </div>
                            
                            ${data.formats ? `
                                <div style='margin-top: 12px; padding: 10px; background: rgba(0, 0, 0, 0.2); border-radius: 4px;'>
                                    <strong>📋 Formatos:</strong><br>
                                    <div style='margin-top: 6px; padding-left: 10px; font-size: 0.9em; font-family: monospace;'>
                                        <div>Internacional: <code style='background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 3px;'>${data.formats.international}</code></div>
                                        <div>Nacional: <code style='background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 3px;'>${data.formats.national}</code></div>
                                        <div>E.164: <code style='background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 3px;'>${data.formats.e164}</code></div>
                                    </div>
                                </div>
                            ` : ''}
                            
                            ${data.timezones && data.timezones.length > 0 ? `
                                <div style='margin-top: 8px; padding-left: 10px;'>
                                    <div>🕐 <strong>Fuso horário:</strong> ${data.timezones.join(', ')}</div>
                                </div>
                            ` : ''}
                        </div>
                    `;
                }
                break;

            case 'phone_analysis':

                if (data.country) {
                    html += `
                        <div style='margin-top: 12px; padding: 12px; background: rgba(0, 243, 255, 0.08); border-radius: 6px;'>
                            <strong style='color: var(--osint-secondary);'>📱 Informações:</strong><br>
                            <div style='margin-top: 8px; padding-left: 10px;'>
                                <div>🌐 País: ${data.country}</div>
                                ${data.ddd ? `<div>📍 DDD: ${data.ddd}</div>` : ''}
                                ${data.type ? `<div>📞 Tipo: ${data.type}</div>` : ''}
                                ${data.format ? `<div>📋 Formato: <code style='background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 3px;'>${data.format}</code></div>` : ''}
                            </div>
                        </div>
                    `;
                }
                break;

            case 'pattern_analysis':
                if (data.patterns && data.patterns.length > 0) {
                    html += `
                        <div style='margin-top: 12px; padding: 12px; background: rgba(255, 160, 0, 0.08); border-radius: 6px;'>
                            <strong style='color: var(--osint-warning);'>🔍 Padrões Identificados:</strong><br>
                            <ul style='margin: 8px 0; padding-left: 20px;'>
                    `;
                    data.patterns.forEach(pattern => {
                        html += `<li>${pattern}</li>`;
                    });
                    html += `
                            </ul>
                        </div>
                    `;
                }
                break;

            case 'validation':
                if (data.is_valid !== undefined) {
                    const icon = data.is_valid ? '✅' : '❌';
                    const color = data.is_valid ? 'var(--osint-success)' : 'var(--osint-danger)';
                    html += `
                        <div style='margin-top: 12px; padding: 12px; background: rgba(0, 255, 157, 0.08); border-radius: 6px;'>
                            <strong style='color: ${color};'>${icon} ${data.is_valid ? 'Formato Válido' : 'Formato Inválido'}</strong>
                            ${data.cleaned_number ? `<br><div style='margin-top: 8px;'>Número limpo: <code style='background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 3px;'>${data.cleaned_number}</code></div>` : ''}
                        </div>
                    `;
                }
                break;

            case 'subdomain_enumeration':
                if (data.subdomains && data.subdomains.length > 0) {
                    html += `
                        <div style='margin-top: 12px; padding: 12px; background: rgba(0, 170, 255, 0.08); border-radius: 6px;'>
                            <strong style='color: var(--osint-info);'>🌐 Subdomínios Detectados:</strong><br>
                            <div style='margin-top: 10px; max-height: 200px; overflow-y: auto; display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 8px;'>
                    `;
                    data.subdomains.forEach(sub => {
                        html += `
                            <div style='background:rgba(0,0,0,0.2); padding:8px; border-radius:4px; font-family:"Roboto Mono"; font-size:0.85em; color: var(--osint-text-muted); display:flex; justify-content:space-between; align-items:center;'>
                                <span style="white-space:nowrap; overflow:hidden; text-overflow:ellipsis; max-width:80%;" title="${sub}">${sub}</span>
                                <a href="/?target=${sub}" target="_blank" title="Escanear Vulnerabilidades" style="text-decoration:none; color: var(--osint-primary); font-weight:bold; padding:2px 6px; border:1px solid var(--osint-primary); border-radius:3px; font-size:0.9em;">
                                    ⚡
                                </a>
                            </div>`;
                    });
                    html += `</div></div>`;
                }
                break;

            case 'manual_verification':
                if (data.username) {
                    html += `
                        <div style='margin-top: 15px; padding: 15px; border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; background: rgba(255,100,0,0.05);'>
                            <div style='margin-bottom: 10px; color: var(--osint-warning); font-weight: bold;'>
                                 🚫 Estas redes frequentemente bloqueiam scanners automáticos. Verifique manualmente:
                            </div>
                            <div style='display: flex; gap: 10px; flex-wrap: wrap;'>
                                <a href='https://instagram.com/${data.username}' target='_blank' style='background: linear-gradient(45deg, #f09433, #e6683c, #dc2743, #cc2366, #bc1888); color: white; padding: 8px 16px; border-radius: 4px; text-decoration: none; font-weight:bold;'>Instagram ↗</a>
                                <a href='https://www.threads.net/@${data.username}' target='_blank' style='background: #111; color: white; border: 1px solid #333; padding: 8px 16px; border-radius: 4px; text-decoration: none; font-weight:bold;'>Threads ↗</a>
                                <a href='https://tiktok.com/@${data.username}' target='_blank' style='background: #000; color: white; border: 1px solid #333; padding: 8px 16px; border-radius: 4px; text-decoration: none; font-weight:bold;'>TikTok ↗</a>
                            </div>
                        </div>
                    `;
                }
                break;

            default:
                // Para tipos desconhecidos, apenas não mostrar JSON cru
                // Deixar só a descrição que já foi adicionada
                break;
        }

        return html;
    }

    displayRecommendations(recommendations) {
        const container = document.getElementById('recommendations-content');
        let html = '<ul style="list-style-type: none; padding: 0;">';

        recommendations.forEach(rec => {
            html += `
                <li style="background: var(--osint-dark-lighter); padding: 1rem; border-radius: 8px; margin-bottom: 0.75rem; border-left: 4px solid var(--osint-warning);">
                    💡 ${rec}
                </li>
            `;
        });

        html += '</ul>';
        container.innerHTML = html;
    }

    showError(message) {
        document.getElementById('progress-indicator').style.display = 'none';
        document.getElementById('results-container').style.display = 'block';
        document.getElementById('action-buttons').style.display = 'flex';

        const container = document.getElementById('findings-content');
        container.innerHTML = `
            <div style="background: var(--osint-danger); color: white; padding: 1.5rem; border-radius: 8px;">
                <h4>❌ Erro na Investigação</h4>
                <p>${message}</p>
            </div>
        `;
    }

    downloadReport(format) {
        if (!this.investigationResults) {
            alert('Nenhum resultado para exportar');
            return;
        }

        if (format === 'json') {
            // Download JSON
            const blob = new Blob([JSON.stringify(this.investigationResults, null, 2)], {
                type: 'application/json'
            });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `osint-report-${Date.now()}.json`;
            a.click();
            URL.revokeObjectURL(url);
        } else if (format === 'pdf') {
            // Redirect to PDF generation endpoint with ID
            let url = '/osint/report/pdf';
            if (this.lastReportId) {
                url += `?id=${this.lastReportId}`;
            }
            window.open(url, '_blank');
        }
    }

    // ==========================================
    // FORM TEMPLATES
    // ==========================================

    getEmailForm() {
        return {
            main: `
                <div class="form-group">
                    <label>📧 Endereço de E-mail</label>
                    <input type="email" name="target" required placeholder="exemplo@dominio.com">
                </div>
            `,
            advanced: `
                <div class="form-check">
                    <input type="checkbox" name="search_username" id="search_username">
                    <label for="search_username">Buscar username em redes sociais (Sherlock/Maigret)</label>
                </div>
            `
        };
    }

    getDomainForm() {
        return {
            main: `
                <div class="form-group">
                    <label>🌐 Domínio ou URL</label>
                    <input type="text" name="target" required placeholder="exemplo.com">
                </div>
            `,
            advanced: `
                <div class="form-check">
                    <input type="checkbox" name="subdomain_enum" id="subdomain_enum" checked>
                    <label for="subdomain_enum">Enumerar subdomínios (Passivo/Rápido)</label>
                </div>
                <div class="form-check">
                    <input type="checkbox" name="ssl_deep" id="ssl_deep" checked>
                    <label for="ssl_deep">Análise profunda de SSL</label>
                </div>
            `
        };
    }

    getPhishingForm() {
        return {
            main: `
                <div class="form-group">
                    <label>🎣 Domínio Suspeito</label>
                    <input type="text" name="target" required placeholder="dominio-suspeito.com">
                </div>
            `,
            advanced: `
                <div class="form-check">
                    <input type="checkbox" name="generate_variations" id="generate_variations" checked>
                    <label for="generate_variations">Gerar variações de typosquatting</label>
                </div>
            `
        };
    }

    getPersonForm() {
        return {
            main: `
                <div class="form-group">
                    <label>👤 Nome ou Username</label>
                    <input type="text" name="target" required placeholder="username ou nome completo">
                </div>
            `,
            advanced: `
                <div class="form-check">
                    <input type="checkbox" name="deep_search" id="deep_search">
                    <label for="deep_search">Busca profunda em redes sociais (mais lento)</label>
                </div>
            `
        };
    }

    getPhoneForm() {
        return {
            main: `
                <div style="background: rgba(0, 170, 255, 0.08); padding: 16px; border-radius: 8px; border-left: 3px solid var(--osint-secondary); margin-bottom: 16px;">
                    <strong style="color: var(--osint-secondary);">💡 Formato Facilitado</strong><br>
                    <span style="font-size: 0.9em; color: var(--osint-text-muted);">Preencha os campos separadamente para melhor precisão</span>
                </div>
                
                <div class="form-group">
                    <label>🌐 País</label>
                    <select name="country" id="phone-country" style="width: 100%; padding: 12px; background: rgba(0, 0, 0, 0.3); border: 1px solid rgba(255, 255, 255, 0.1); color: var(--osint-text); border-radius: 6px; font-size: 1rem;">
                        <option value="+55">🇧🇷 Brasil (+55)</option>
                        <option value="+1">🇺🇸 EUA / Canadá (+1)</option>
                        <option value="+44">🇬🇧 Reino Unido (+44)</option>
                        <option value="+33">🇫🇷 França (+33)</option>
                        <option value="+49">🇩🇪 Alemanha (+49)</option>
                        <option value="+34">🇪🇸 Espanha (+34)</option>
                        <option value="+39">🇮🇹 Itália (+39)</option>
                        <option value="+351">🇵🇹 Portugal (+351)</option>
                        <option value="+54">🇦🇷 Argentina (+54)</option>
                        <option value="+52">🇲🇽 México (+52)</option>
                        <option value="+81">🇯🇵 Japão (+81)</option>
                        <option value="+86">🇨🇳 China (+86)</option>
                        <option value="">➕ Outro (digite código)</option>
                    </select>
                </div>
                
                <div id="brazil-fields" style="display: grid; grid-template-columns: 1fr 2fr; gap: 12px; margin-bottom: 16px;">
                    <div class="form-group" style="margin-bottom: 0;">
                        <label>📍 DDD</label>
                        <input type="text" id="phone-ddd" placeholder="11" maxlength="2" style="width: 100%; padding: 12px; background: rgba(0, 0, 0, 0.3); border: 1px solid rgba(255, 255, 255, 0.1); color: var(--osint-text); border-radius: 6px; font-size: 1rem;">
                        <div style="font-size: 0.8em; color: var(--osint-text-muted); margin-top: 4px;">Apenas 2 números</div>
                    </div>
                    
                    <div class="form-group" style="margin-bottom: 0;">
                        <label>📱 Número</label>
                        <input type="text" id="phone-number" placeholder="912345678" maxlength="10" style="width: 100%; padding: 12px; background: rgba(0, 0, 0, 0.3); border: 1px solid rgba(255, 255, 255, 0.1); color: var(--osint-text); border-radius: 6px; font-size: 1rem;">
                        <div style="font-size: 0.8em; color: var(--osint-text-muted); margin-top: 4px;">Digite só números - formatação automática</div>
                    </div>
                </div>
                
                <div id="international-field" style="display: none; margin-bottom: 16px;">
                    <div class="form-group">
                        <label>📞 Número Completo</label>
                        <input type="tel" id="phone-international" placeholder="2025551234" style="width: 100%; padding: 12px; background: rgba(0, 0, 0, 0.3); border: 1px solid rgba(255, 255, 255, 0.1); color: var(--osint-text); border-radius: 6px; font-size: 1rem;">
                        <div style="font-size: 0.8em; color: var(--osint-text-muted); margin-top: 4px;">Apenas números - aceita qualquer formato</div>
                    </div>
                </div>
                
                <!-- Hidden input que será preenchido com número completo -->
                <input type="hidden" name="target" id="phone-final">
                
                <div id="phone-preview" style="margin-top: 12px; padding: 12px; background: rgba(0, 255, 157, 0.08); border-radius: 6px; border-left: 3px solid var(--osint-success); display: none;">
                    <strong style="color: var(--osint-success);">✓ Número Formatado:</strong><br>
                    <code style="font-size: 1.1em; color: var(--osint-primary); background: rgba(0, 0, 0, 0.3); padding: 4px 8px; border-radius: 4px; display: inline-block; margin-top: 6px;" id="phone-display"></code>
                </div>
                
                <script>
                    (function() {
                        const countrySelect = document.getElementById('phone-country');
                        const brazilFields = document.getElementById('brazil-fields');
                        const internationalField = document.getElementById('international-field');
                        const dddInput = document.getElementById('phone-ddd');
                        const numberInput = document.getElementById('phone-number');
                        const internationalInput = document.getElementById('phone-international');
                        const finalInput = document.getElementById('phone-final');
                        const preview = document.getElementById('phone-preview');
                        const display = document.getElementById('phone-display');
                        
                        function updateFields() {
                            const country = countrySelect.value;
                            
                            if (country === '+55') {
                                brazilFields.style.display = 'grid';
                                internationalField.style.display = 'none';
                                internationalInput.required = false;
                                numberInput.required = true;
                            } else {
                                brazilFields.style.display = 'none';
                                internationalField.style.display = 'block';
                                internationalInput.required = true;
                                numberInput.required = false;
                                dddInput.required = false;
                            }
                            
                            updatePreview();
                        }
                        
                        function updatePreview() {
                            const country = countrySelect.value;
                            let fullNumber = '';
                            
                            if (country === '+55') {
                                const ddd = dddInput.value.replace(/\D/g, '');
                                const number = numberInput.value.replace(/\D/g, '');
                                
                                if (ddd && number) {
                                    fullNumber = '+55 ' + ddd + ' ' + number;
                                    finalInput.value = fullNumber;
                                    display.textContent = fullNumber;
                                    preview.style.display = 'block';
                                } else {
                                    preview.style.display = 'none';
                                    finalInput.value = '';
                                }
                            } else if (country) {
                                const number = internationalInput.value.replace(/\D/g, '');
                                if (number) {
                                    fullNumber = country + ' ' + number;
                                    finalInput.value = fullNumber;
                                    display.textContent = fullNumber;
                                    preview.style.display = 'block';
                                } else {
                                    preview.style.display = 'none';
                                    finalInput.value = '';
                                }
                            } else {
                                // Outro código - deixar usuário digitar completo
                                const number = internationalInput.value;
                                if (number) {
                                    finalInput.value = number;
                                    display.textContent = number;
                                    preview.style.display = 'block';
                                } else {
                                    preview.style.display = 'none';
                                    finalInput.value = '';
                                }
                            }
                        }
                        
                        // Auto-formatar DDD (só números)
                        dddInput.addEventListener('input', function(e) {
                            // Remove tudo que não é número
                            this.value = this.value.replace(/\D/g, '');
                            // Limita a 2 dígitos
                            if (this.value.length > 2) {
                                this.value = this.value.substring(0, 2);
                            }
                            updatePreview();
                        });
                        
                        // Auto-formatar número (ACEITA QUALQUER FORMATO)
                        numberInput.addEventListener('input', function(e) {
                            // Remove tudo que não é número
                            let value = this.value.replace(/\D/g, '');
                            
                            // Limita a 9 dígitos (celular)
                            if (value.length > 9) {
                                value = value.substring(0, 9);
                            }
                            
                            // Formata SOMENTE para visualização (não bloqueia input)
                            // Usuário pode digitar com ou sem traço
                            if (value.length > 5) {
                                this.value = value.substring(0, 5) + '-' + value.substring(5);
                            } else {
                                this.value = value;
                            }
                            
                            updatePreview();
                        });
                        
                        // Aceita QUALQUER formato no campo internacional
                        internationalInput.addEventListener('input', function(e) {
                            // Remove tudo que não é número
                            let cleaned = this.value.replace(/\D/g, '');
                            // Mantém o valor como está (aceita espaços, traços, etc)
                            // Mas usa apenas números para validação
                            updatePreview();
                        });
                        
                        // Mudar país
                        countrySelect.addEventListener('change', updateFields);
                        
                        // Inicializar
                        updateFields();
                    })();
                </script>
            `,
            advanced: `
                <div class="form-check">
                    <input type="checkbox" name="validate_only" id="validate_only">
                    <label for="validate_only">Apenas validar (sem busca de operadora)</label>
                </div>
            `
        };
    }
}

// Initialize controller when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    new OsintController();
});
