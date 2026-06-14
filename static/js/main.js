// Utility function to get CSS variable values
function getCssVariable(name) {
    const val = getComputedStyle(document.documentElement).getPropertyValue(name);
    return val ? val.trim() : '';
}

// Global Chart References
let riskGaugeChart = null;
let indexTrendChart = null;
let indexPieChart = null;

document.addEventListener('DOMContentLoaded', () => {
    const csrfTokenElement = document.querySelector('meta[name="csrf-token"]');
    const csrfToken = csrfTokenElement ? csrfTokenElement.getAttribute('content') : '';

    // ----------------------------------------------------
    // SUGGESTION CHIPS LOGIC
    // ----------------------------------------------------
    const suggestionChips = document.querySelectorAll('.suggestion-chip');
    suggestionChips.forEach(chip => {
        chip.addEventListener('click', () => {
            const fillValue = chip.getAttribute('data-fill');
            const tabPane = chip.closest('.tab-pane');
            if (tabPane && fillValue) {
                const textInput = tabPane.querySelector('input[type="text"]');
                if (textInput) {
                    textInput.value = fillValue;
                    textInput.focus();
                }
            }
        });
    });

    // ----------------------------------------------------
    // SMOOTH SCROLL FOR ANCHORS
    // ----------------------------------------------------
    const quickScanLink = document.querySelector('a[href="#scan-section"]');
    if (quickScanLink) {
        quickScanLink.addEventListener('click', (e) => {
            e.preventDefault();
            const target = document.getElementById('scan-section');
            if (target) {
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        });
    }

    // ----------------------------------------------------
    // NOTIFICATIONS PANEL (CSP COMPLIANT)
    // ----------------------------------------------------
    const notifBadge = document.getElementById('notifBadge');
    const notifList = document.getElementById('notifList');
    const markAllReadBtn = document.getElementById('markAllReadBtn');
    
    function fetchNotifications() {
        if (!notifList) return;
        fetch('/notifications')
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    if (data.unread_count > 0) {
                        if (notifBadge) {
                            notifBadge.textContent = data.unread_count;
                            notifBadge.classList.remove('d-none');
                        }
                    } else {
                        if (notifBadge) notifBadge.classList.add('d-none');
                    }
                    
                    if (data.notifications.length === 0) {
                        notifList.innerHTML = '<div class="p-3 text-center text-muted">No new security logs.</div>';
                    } else {
                        notifList.innerHTML = data.notifications.map(n => `
                            <div class="p-3 border-bottom border-secondary border-opacity-10 ${n.is_read ? '' : 'bg-info bg-opacity-5'}" id="notif-item-${n.id}" style="transition: all 0.2s;">
                                <div class="d-flex justify-content-between align-items-start mb-1">
                                    <strong class="text-white small d-flex align-items-center gap-2">
                                        <span class="d-inline-block rounded-circle bg-danger" style="width: 5px; height: 5px; display: ${n.is_read ? 'none' : 'inline-block'}"></span>
                                        ${n.title}
                                    </strong>
                                    <div class="d-flex gap-2">
                                        ${!n.is_read ? `<button class="btn btn-link p-0 text-info mark-read-btn" data-id="${n.id}" title="Mark read"><i class="fas fa-check"></i></button>` : ''}
                                        <button class="btn btn-link p-0 text-danger delete-notif-btn" data-id="${n.id}" title="Delete alert"><i class="fas fa-trash-can"></i></button>
                                    </div>
                                </div>
                                <p class="text-secondary mb-1" style="font-size: 0.75rem; line-height:1.3">${n.message}</p>
                                <span class="text-muted" style="font-size: 0.65rem;">${n.created_at}</span>
                            </div>
                        `).join('');
                    }
                }
            })
            .catch(err => console.error("Error loading index notifications:", err));
    }
    
    if (notifList) {
        notifList.addEventListener('click', (e) => {
            const markBtn = e.target.closest('.mark-read-btn');
            const deleteBtn = e.target.closest('.delete-notif-btn');
            
            if (markBtn) {
                e.stopPropagation();
                const notifId = markBtn.dataset.id;
                fetch(`/notifications/read/${notifId}`, {
                    method: 'POST',
                    headers: { 'X-CSRFToken': csrfToken }
                }).then(() => fetchNotifications());
            }
            
            if (deleteBtn) {
                e.stopPropagation();
                const notifId = deleteBtn.dataset.id;
                fetch(`/notifications/delete/${notifId}`, {
                    method: 'DELETE',
                    headers: { 'X-CSRFToken': csrfToken }
                }).then(() => fetchNotifications());
            }
        });
    }

    if (markAllReadBtn) {
        markAllReadBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            fetch('/notifications/read-all', {
                method: 'POST',
                headers: { 'X-CSRFToken': csrfToken }
            }).then(() => fetchNotifications());
        });
    }
    
    fetchNotifications();
    setInterval(fetchNotifications, 30000);

    // ----------------------------------------------------
    // LANDING ANALYTICS CHARTS
    // ----------------------------------------------------
    initializeLandingCharts();

    function initializeLandingCharts() {
        const trendCanvas = document.getElementById('indexTrendCanvas');
        if (!trendCanvas) return;

        const dailyData = JSON.parse(trendCanvas.dataset.dailyScans || '[]');
        const sortedData = [...dailyData].reverse();
        
        const labels = sortedData.map(d => {
            const date = new Date(d.date);
            return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
        });
        const totalCounts = sortedData.map(d => d.count || 0);

        // Chart 1: Volume Trend (Line)
        indexTrendChart = new Chart(trendCanvas, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Audit Traffic',
                    data: totalCounts,
                    borderColor: '#00e5ff',
                    backgroundColor: 'rgba(0, 229, 255, 0.05)',
                    fill: true,
                    tension: 0.4,
                    borderWidth: 2,
                    pointRadius: 2,
                    pointBackgroundColor: '#00e5ff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { grid: { display: false }, ticks: { color: '#4b5563', font: { size: 8 } } },
                    y: { grid: { color: 'rgba(255, 255, 255, 0.03)' }, ticks: { color: '#4b5563', font: { size: 8 } } }
                },
                plugins: {
                    legend: { display: false },
                    tooltip: { backgroundColor: '#0b0f19', borderColor: 'rgba(0, 229, 255, 0.2)', borderWidth: 1 }
                }
            }
        });

        // Chart 2: Category breakdown (Doughnut)
        const pieCanvas = document.getElementById('indexPieCanvas');
        if (pieCanvas) {
            const phishVal = parseInt(pieCanvas.dataset.phishing || '0');
            const suspVal = parseInt(pieCanvas.dataset.suspicious || '0');
            const safeVal = parseInt(pieCanvas.dataset.legitimate || '0');

            indexPieChart = new Chart(pieCanvas, {
                type: 'doughnut',
                data: {
                    labels: ['Safe', 'Suspicious', 'Phishing'],
                    datasets: [{
                        data: [safeVal, suspVal, phishVal],
                        backgroundColor: ['#10b981', '#f59e0b', '#ef4444'],
                        borderWidth: 1,
                        borderColor: '#0b0f19'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '70%',
                    plugins: {
                        legend: { display: false },
                        tooltip: { backgroundColor: '#0b0f19', borderColor: 'rgba(0, 229, 255, 0.2)', borderWidth: 1 }
                    }
                }
            });
        }
    }

    // ----------------------------------------------------
    // URL SCAN HANDLER
    // ----------------------------------------------------
    const urlScanForm = document.getElementById('urlScanForm');
    if (urlScanForm) {
        urlScanForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const urlInput = document.getElementById('urlInput').value.trim();
            if (!urlInput) return;

            showLoading('url-loading');
            hideResult('url-result');

            try {
                const formData = new FormData();
                formData.append('url', urlInput);

                const response = await fetch('/scan/url', {
                    method: 'POST',
                    headers: { 'X-CSRFToken': csrfToken },
                    body: formData
                });
                
                const res = await response.json();
                if (res.success) {
                    displayUrlResult(res.data);
                } else {
                    showError('url-result', res.error || 'Scan failed');
                }
            } catch (err) {
                showError('url-result', 'Connection to security engine lost.');
            } finally {
                hideLoading('url-loading');
            }
        });
    }

    // ----------------------------------------------------
    // QR CODE SCAN HANDLER
    // ----------------------------------------------------
    const qrScanForm = document.getElementById('qrScanForm');
    if (qrScanForm) {
        qrScanForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const fileInput = document.getElementById('qrFileInput');
            if (fileInput.files.length === 0) return;

            showLoading('qr-loading');
            hideResult('qr-result');

            try {
                const formData = new FormData();
                formData.append('file', fileInput.files[0]);

                const response = await fetch('/scan/qrcode', {
                    method: 'POST',
                    headers: { 'X-CSRFToken': csrfToken },
                    body: formData
                });
                
                const res = await response.json();
                if (res.success) {
                    displayQrResult(res.data);
                } else {
                    showError('qr-result', res.error || 'QR Scan failed');
                }
            } catch (err) {
                showError('qr-result', 'Connection to QR processor failed.');
            } finally {
                hideLoading('qr-loading');
            }
        });
    }

    // ----------------------------------------------------
    // EMAIL SCAN HANDLER
    // ----------------------------------------------------
    const emailScanForm = document.getElementById('emailScanForm');
    if (emailScanForm) {
        emailScanForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const emailText = document.getElementById('emailTextInput').value.trim();
            const emlFile = document.getElementById('emlFileInput').files[0];

            if (!emailText && !emlFile) {
                alert("Please enter email text or upload a .eml file.");
                return;
            }

            showLoading('email-loading');
            hideResult('email-result');

            try {
                const formData = new FormData();
                if (emlFile) {
                    formData.append('file', emlFile);
                } else {
                    formData.append('email_text', emailText);
                }

                const response = await fetch('/scan/email', {
                    method: 'POST',
                    headers: { 'X-CSRFToken': csrfToken },
                    body: formData
                });
                
                const res = await response.json();
                if (res.success) {
                    displayEmailResult(res.data);
                } else {
                    showError('email-result', res.error || 'Email analysis failed');
                }
            } catch (err) {
                showError('email-result', 'Connection to Email analyzer failed.');
            } finally {
                hideLoading('email-loading');
            }
        });
    }

    // ----------------------------------------------------
    // SCREENSHOT SCAN HANDLER
    // ----------------------------------------------------
    const screenshotForm = document.getElementById('screenshotForm');
    if (screenshotForm) {
        screenshotForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const urlInput = document.getElementById('screenshotUrlInput').value.trim();
            if (!urlInput) return;

            showLoading('ss-loading');
            hideResult('ss-result');

            try {
                const formData = new FormData();
                formData.append('url', urlInput);

                const response = await fetch('/scan/screenshot', {
                    method: 'POST',
                    headers: { 'X-CSRFToken': csrfToken },
                    body: formData
                });
                
                const res = await response.json();
                if (res.success) {
                    displayScreenshotResult(res.data);
                } else {
                    showError('ss-result', res.error || 'Screenshot rendering failed');
                }
            } catch (err) {
                showError('ss-result', 'Connection to rendering sandbox failed.');
            } finally {
                hideLoading('ss-loading');
            }
        });
    }

    // ----------------------------------------------------
    // DOMAIN INTELLIGENCE HANDLER (5TH TAB)
    // ----------------------------------------------------
    const domainIntelForm = document.getElementById('domainIntelForm');
    if (domainIntelForm) {
        domainIntelForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            let domainInput = document.getElementById('domainIntelInput').value.trim();
            if (!domainInput) return;

            // Simple validation: prefix with http:// if it's a raw domain name
            if (!domainInput.startsWith('http://') && !domainInput.startsWith('https://')) {
                domainInput = 'http://' + domainInput;
            }

            showLoading('domain-loading');
            hideResult('domain-result');

            try {
                const formData = new FormData();
                formData.append('url', domainInput);

                const response = await fetch('/scan/url', {
                    method: 'POST',
                    headers: { 'X-CSRFToken': csrfToken },
                    body: formData
                });
                
                const res = await response.json();
                if (res.success) {
                    displayDomainResult(res.data);
                } else {
                    showError('domain-result', res.error || 'Domain lookup failed');
                }
            } catch (err) {
                showError('domain-result', 'Failed to resolve DNS indicators.');
            } finally {
                hideLoading('domain-loading');
            }
        });
    }
});

// Helper functions for loaders
function showLoading(id) {
    const el = document.getElementById(id);
    if (el) el.classList.remove('d-none');
}

function hideLoading(id) {
    const el = document.getElementById(id);
    if (el) el.classList.add('d-none');
}

function hideResult(id) {
    const el = document.getElementById(id);
    if (el) el.classList.add('d-none');
}

function showError(resultId, message) {
    const el = document.getElementById(resultId);
    if (!el) return;
    el.innerHTML = `
        <div class="cyber-card card-danger mt-4">
            <h5 class="text-danger"><i class="fas fa-exclamation-triangle"></i> Engine Error</h5>
            <p class="text-secondary">${message}</p>
        </div>
    `;
    el.classList.remove('d-none');
}

// ----------------------------------------------------
// UI DISPLAY LOGIC
// ----------------------------------------------------

function displayUrlResult(data) {
    const el = document.getElementById('url-result');
    if (!el) return;

    el.classList.remove('d-none');
    
    // Set badge style
    let badgeClass = 'badge-legitimate';
    let textClass = 'text-success';
    if (data.prediction === 'Phishing') {
        badgeClass = 'badge-phishing';
        textClass = 'text-danger';
    } else if (data.prediction === 'Suspicious') {
        badgeClass = 'badge-suspicious';
        textClass = 'text-warning';
    }

    // Parse details
    const intel = data.details || {};
    const whois = intel.whois || {};
    const ssl = intel.ssl || {};
    const dns = intel.dns || {};
    const features = intel.features || {};

    el.innerHTML = `
        <div class="row g-4 mt-2">
            <!-- Summary card -->
            <div class="col-md-5">
                <div class="cyber-card ${data.prediction === 'Phishing' ? 'card-danger' : data.prediction === 'Suspicious' ? 'card-warning' : 'card-success'} h-100">
                    <h5 class="brand-font ${textClass}">ANALYST VERDICT</h5>
                    <div class="d-flex justify-content-between align-items-center mt-3 mb-4">
                        <span class="neon-badge ${badgeClass}">${data.prediction.toUpperCase()}</span>
                        <span class="brand-font h4 mb-0 text-white">${data.risk_score}% Risk</span>
                    </div>
                    
                    <div class="chart-container" style="position: relative; height:200px; width:100%">
                        <canvas id="riskGaugeCanvas"></canvas>
                    </div>
                    
                    <div class="mt-3">
                        <small class="text-muted d-block">Target Resource:</small>
                        <code class="text-break text-info" style="font-size:0.85rem">${data.url}</code>
                    </div>
                    
                    <div class="mt-4 pt-3 border-top border-secondary">
                        <a href="/report/download/${data.scan_id}" class="btn btn-cyber w-100">
                            <i class="fas fa-file-pdf"></i> DOWNLOAD PDF REPORT
                        </a>
                    </div>
                </div>
            </div>

            <!-- Threat Intel details -->
            <div class="col-md-7">
                <div class="cyber-card h-100">
                    <ul class="nav nav-tabs cyber-nav-tabs mb-3" id="intelTab" role="tablist">
                        <li class="nav-item">
                            <button class="nav-link active" id="intel-summary-tab" data-bs-toggle="tab" data-bs-target="#intel-summary" type="button">Indicators</button>
                        </li>
                        <li class="nav-item">
                            <button class="nav-link" id="intel-whois-tab" data-bs-toggle="tab" data-bs-target="#intel-whois" type="button">WHOIS</button>
                        </li>
                        <li class="nav-item">
                            <button class="nav-link" id="intel-ssl-tab" data-bs-toggle="tab" data-bs-target="#intel-ssl" type="button">SSL/TLS</button>
                        </li>
                        <li class="nav-item">
                            <button class="nav-link" id="intel-dns-tab" data-bs-toggle="tab" data-bs-target="#intel-dns" type="button">DNS Records</button>
                        </li>
                    </ul>
                    
                    <div class="tab-content" id="intelTabContent">
                        <!-- Indicators -->
                        <div class="tab-pane fade show active" id="intel-summary">
                            <h6 class="text-info brand-font mb-3">Lexical & Structural Markers</h6>
                            <div class="row g-2">
                                ${renderIndicatorRow("HTTPS Connection", features.has_https === 1, features.has_https === 1 ? "Secure connection protocol" : "Unencrypted plain HTTP")}
                                ${renderIndicatorRow("IP Address URL", features.has_ip === 1, features.has_ip === 1 ? "Domain uses raw IP" : "Standard Domain name resolution")}
                                ${renderIndicatorRow("Subdomain Nesting", features.num_subdomains > 1, `Found ${features.num_subdomains} subdomains`)}
                                ${renderIndicatorRow("Suspicious Keywords", features.suspicious_keywords > 0, `Found ${features.suspicious_keywords} brand/login keywords`)}
                                ${renderIndicatorRow("URL Redirection", features.has_redirect === 1, features.has_redirect === 1 ? "Redirect loop detected" : "Direct response")}
                                ${renderIndicatorRow("Link Shortener", features.is_shortener === 1, features.is_shortener === 1 ? "Shortener domain masks endpoint" : "Standard path")}
                                ${renderIndicatorRow("Shannon Entropy", features.entropy > 4.2, `Randomness Score: ${features.entropy}`)}
                            </div>
                        </div>

                        <!-- WHOIS -->
                        <div class="tab-pane fade" id="intel-whois">
                            <h6 class="text-info brand-font mb-3">WHOIS Domain Registration</h6>
                            <table class="table table-borderless text-light table-sm">
                                <tr><td><strong>Domain:</strong></td><td class="text-secondary">${whois.domain || 'N/A'}</td></tr>
                                <tr><td><strong>Registrar:</strong></td><td class="text-secondary">${whois.registrar || 'N/A'}</td></tr>
                                <tr><td><strong>Creation Date:</strong></td><td class="text-secondary">${whois.creation_date || 'Unknown'}</td></tr>
                                <tr><td><strong>Expiration Date:</strong></td><td class="text-secondary">${whois.expiration_date || 'Unknown'}</td></tr>
                                <tr><td><strong>Domain Age:</strong></td><td class="text-secondary">${whois.domain_age_days !== -1 ? whois.domain_age_days + ' days' : 'Unknown'}</td></tr>
                                <tr><td><strong>Query Status:</strong></td><td><span class="badge ${whois.status && whois.status.includes('Success') ? 'bg-success' : 'bg-warning'}">${whois.status || 'N/A'}</span></td></tr>
                            </table>
                        </div>

                        <!-- SSL -->
                        <div class="tab-pane fade" id="intel-ssl">
                            <h6 class="text-info brand-font mb-3">SSL Certificate Properties</h6>
                            <table class="table table-borderless text-light table-sm">
                                <tr><td><strong>Has SSL/TLS:</strong></td><td><span class="badge ${ssl.has_ssl ? 'bg-success' : 'bg-danger'}">${ssl.has_ssl ? 'YES' : 'NO'}</span></td></tr>
                                <tr><td><strong>Verification:</strong></td><td><span class="badge ${ssl.verified ? 'bg-success' : 'bg-warning'}">${ssl.verified ? 'VERIFIED TRUSTED' : 'UNTRUSTED/SELF-SIGNED'}</span></td></tr>
                                <tr><td><strong>Issuer:</strong></td><td class="text-secondary">${ssl.issuer || 'N/A'}</td></tr>
                                <tr><td><strong>Subject Name:</strong></td><td class="text-secondary">${ssl.subject || 'N/A'}</td></tr>
                                <tr><td><strong>Remaining Days:</strong></td><td class="text-secondary">${ssl.days_remaining !== -1 ? ssl.days_remaining + ' days' : 'N/A'}</td></tr>
                                <tr><td><strong>Expiry Date:</strong></td><td class="text-secondary">${ssl.valid_to || 'N/A'}</td></tr>
                            </table>
                        </div>

                        <!-- DNS -->
                        <div class="tab-pane fade" id="intel-dns">
                            <h6 class="text-info brand-font mb-3">DNS Server Lookup</h6>
                            <div class="dns-records">
                                ${renderDnsRow("A Records (IP Resolution)", dns.A)}
                                ${renderDnsRow("MX Records (Mail Exchanger)", dns.MX)}
                                ${renderDnsRow("NS Records (Name Server)", dns.NS)}
                                ${renderDnsRow("TXT Records", dns.TXT)}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Draw Gauge Chart
    setTimeout(() => {
        renderGaugeChart(data.risk_score);
    }, 100);
}

function renderIndicatorRow(label, isTriggered, desc) {
    const icon = isTriggered ? '<i class="fas fa-exclamation-circle text-danger"></i>' : '<i class="fas fa-check-circle text-success"></i>';
    const border = isTriggered ? 'border-danger-subtle' : 'border-success-subtle';
    return `
        <div class="col-12">
            <div class="d-flex align-items-center p-2 rounded bg-black bg-opacity-20 border ${border}">
                <div class="me-3">${icon}</div>
                <div>
                    <strong class="d-block" style="font-size:0.85rem">${label}</strong>
                    <span class="text-muted" style="font-size:0.75rem">${desc}</span>
                </div>
            </div>
        </div>
    `;
}

function renderDnsRow(title, list) {
    if (!list || list.length === 0) {
        return `
            <div class="mb-2">
                <span class="text-muted font-monospace" style="font-size:0.8rem">${title}</span>
                <div class="text-secondary font-monospace" style="font-size:0.8rem; padding-left:10px">- None found -</div>
            </div>
        `;
    }
    return `
        <div class="mb-2">
            <span class="text-muted font-monospace" style="font-size:0.8rem">${title}</span>
            <ul class="text-secondary font-monospace mb-0" style="font-size:0.8rem; padding-left:20px">
                ${list.map(r => `<li>${r}</li>`).join('')}
            </ul>
        </div>
    `;
}

function displayQrResult(data) {
    const el = document.getElementById('qr-result');
    if (!el) return;
    el.classList.remove('d-none');
    
    let verdictClass = 'text-success';
    if (data.prediction === 'Phishing') verdictClass = 'text-danger';
    else if (data.prediction === 'Suspicious') verdictClass = 'text-warning';
    
    el.innerHTML = `
        <div class="cyber-card mt-4">
            <h5 class="brand-font text-info"><i class="fas fa-qrcode"></i> QR CODE ANALYZED</h5>
            <div class="alert alert-dark mt-3">
                <strong>Decoded URL:</strong> <code class="text-info text-break">${data.qr_decoded_url}</code>
            </div>
            
            <div class="row align-items-center mt-3">
                <div class="col-md-8">
                    <p class="mb-1"><strong>Scan ID:</strong> SEC-${data.scan_id}</p>
                    <p class="mb-1"><strong>Safety Verdict:</strong> <span class="fw-bold ${verdictClass}">${data.prediction}</span></p>
                    <p class="mb-0"><strong>AI Risk Score:</strong> ${data.risk_score}%</p>
                </div>
                <div class="col-md-4 text-md-end mt-2 mt-md-0">
                    <a href="/report/download/${data.scan_id}" class="btn btn-cyber btn-sm">
                        <i class="fas fa-file-pdf"></i> View Detailed Report
                    </a>
                </div>
            </div>
        </div>
    `;
}

function displayEmailResult(data) {
    const el = document.getElementById('email-result');
    if (!el) return;
    el.classList.remove('d-none');
    
    let verdictClass = 'badge-legitimate';
    let textClass = 'text-success';
    if (data.verdict === 'Phishing') {
        verdictClass = 'badge-phishing';
        textClass = 'text-danger';
    } else if (data.verdict === 'Suspicious') {
        verdictClass = 'badge-suspicious';
        textClass = 'text-warning';
    }
    
    let linkReportHtml = '';
    if (data.scanned_links.length > 0) {
        linkReportHtml = `
            <h6 class="text-info brand-font mt-4">Embedded Links Scan Analysis</h6>
            <div class="table-responsive">
                <table class="table table-dark table-striped table-sm mt-2 font-monospace" style="font-size:0.8rem">
                    <thead>
                        <tr><th>URL Link</th><th>Risk</th><th>Verdict</th></tr>
                    </thead>
                    <tbody>
                        ${data.scanned_links.map(l => `
                            <tr>
                                <td class="text-break">${l.url}</td>
                                <td>${l.risk_score}%</td>
                                <td><span class="text-${l.prediction === 'Phishing' ? 'danger' : l.prediction === 'Suspicious' ? 'warning' : 'success'}">${l.prediction}</span></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    }

    el.innerHTML = `
        <div class="cyber-card ${data.verdict === 'Phishing' ? 'card-danger' : data.verdict === 'Suspicious' ? 'card-warning' : 'card-success'} mt-4">
            <h5 class="brand-font ${textClass}"><i class="fas fa-envelope-open-text"></i> EMAIL PHISHING RISK ANALYSIS</h5>
            
            <div class="row mt-3">
                <div class="col-md-6">
                    <table class="table table-borderless text-light table-sm">
                        <tr><td><strong>Sender:</strong></td><td class="text-secondary">${data.sender}</td></tr>
                        <tr><td><strong>Subject:</strong></td><td class="text-secondary">${data.subject}</td></tr>
                        <tr><td><strong>Links Found:</strong></td><td class="text-secondary">${data.links_found}</td></tr>
                    </table>
                </div>
                <div class="col-md-6 text-md-end">
                    <div class="mb-2"><span class="neon-badge ${verdictClass}">${data.verdict.toUpperCase()}</span></div>
                    <h4 class="brand-font text-white mb-0">Spam Score: ${data.score}%</h4>
                </div>
            </div>
            
            ${data.spoof_alert ? `
                <div class="alert alert-danger mt-3">
                    <i class="fas fa-exclamation-triangle"></i> <strong>SENDER SPOOFING DETECTED:</strong> The sender's domain closely mimics a known organization's domain but is sent from an unofficial hostname!
                </div>
            ` : ''}

            <div class="row mt-3 g-2">
                <div class="col-md-6">
                    <div class="p-3 bg-black bg-opacity-20 border rounded">
                        <strong class="text-muted d-block mb-2">Urgency & Threats Keywords Found:</strong>
                        ${data.urgency_keywords.length > 0 ? 
                            data.urgency_keywords.map(kw => `<span class="badge bg-danger me-1 mb-1">${kw}</span>`).join('') :
                            '<span class="text-success" style="font-size:0.85rem">None detected</span>'
                        }
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="p-3 bg-black bg-opacity-20 border rounded">
                        <strong class="text-muted d-block mb-2">Core Summary:</strong>
                        <span class="text-secondary" style="font-size:0.85rem">
                            ${data.verdict === 'Phishing' ? 'This message exhibits critical vectors associated with credential theft campaigns.' :
                              data.verdict === 'Suspicious' ? 'Elevated alert level. Examine all embedded urls before clicking.' :
                              'No critical malicious attributes detected.'}
                        </span>
                    </div>
                </div>
            </div>
            
            ${linkReportHtml}
        </div>
    `;
}

function displayScreenshotResult(data) {
    const el = document.getElementById('ss-result');
    if (!el) return;
    el.classList.remove('d-none');
    
    let alertClass = 'alert-info';
    let textClass = 'text-info';
    if (data.spoofing_risk === 'CRITICAL') {
        alertClass = 'alert-danger';
        textClass = 'text-danger';
    }
    
    el.innerHTML = `
        <div class="cyber-card mt-4">
            <h5 class="brand-font text-info"><i class="fas fa-desktop"></i> VISUAL BRAND SPOOFING CHECK</h5>
            
            <div class="row mt-3 g-4">
                <div class="col-md-6">
                    <img src="${data.screenshot_url}" class="screenshot-preview" alt="Sandboxed Screenshot" style="max-width:100%; border:1px solid rgba(255,255,255,0.05); border-radius:6px;">
                </div>
                <div class="col-md-6">
                    <div class="alert ${alertClass}">
                        <h6 class="alert-heading brand-font fw-bold"><i class="fas fa-fingerprint"></i> Visual Risk: ${data.spoofing_risk}</h6>
                        <p class="mb-0">Brand Impersonation Index: <strong>${data.visual_risk_score}%</strong></p>
                    </div>
                    
                    <table class="table table-borderless text-light table-sm mt-3">
                        <tr><td><strong>Resolved Domain:</strong></td><td class="text-secondary font-monospace">${data.domain}</td></tr>
                        <tr><td><strong>Mimicked Brand Assets:</strong></td><td class="text-secondary">${data.mimicked_brand}</td></tr>
                    </table>
                    
                    <div class="p-3 bg-black bg-opacity-20 border border-secondary-subtle rounded mt-3">
                        <strong class="d-block mb-1 text-info" style="font-size:0.85rem">AI Computer Vision Logic:</strong>
                        <span class="text-secondary" style="font-size:0.85rem">
                            ${data.spoofing_risk === 'CRITICAL' ? 
                              `WARNING: The page is visually utilizing branding, styles, and buttons associated with <strong>${data.mimicked_brand}</strong>, but is hosted on a completely unauthorized domain name. This indicates an active credential phishing attack.` : 
                              `No visual brand spoofing signatures matching popular financial or corporate entities were resolved.`}
                        </span>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// ----------------------------------------------------
// DOMAIN INTEL RESULTS DISPLAY (5TH TAB)
// ----------------------------------------------------
function displayDomainResult(data) {
    const el = document.getElementById('domain-result');
    if (!el) return;
    el.classList.remove('d-none');

    const intel = data.details || {};
    const whois = intel.whois || {};
    const ssl = intel.ssl || {};
    const dns = intel.dns || {};

    let badgeClass = 'badge-soc-success';
    if (data.prediction === 'Phishing') badgeClass = 'badge-soc-danger';
    else if (data.prediction === 'Suspicious') badgeClass = 'badge-soc-warning';

    el.innerHTML = `
        <div class="cyber-card mt-4">
            <div class="d-flex justify-content-between align-items-center mb-3 pb-2 border-bottom border-secondary border-opacity-20">
                <h5 class="brand-font text-info m-0"><i class="fas fa-shield-halved"></i> DOMAIN REPUTATION & INDICATORS</h5>
                <span class="badge-soc ${badgeClass}">${data.prediction.toUpperCase()}</span>
            </div>

            <div class="row g-3">
                <!-- Left: Whois Registry & SSL -->
                <div class="col-md-6">
                    <div class="p-3 bg-black bg-opacity-20 rounded border border-secondary border-opacity-10 h-100">
                        <strong class="text-info font-monospace d-block mb-2 small"><i class="fas fa-id-card"></i> WHOIS & SSL Details</strong>
                        <table class="table table-borderless text-light table-sm small mb-0">
                            <tr><td><strong>Domain:</strong></td><td class="text-secondary font-monospace">${whois.domain || 'N/A'}</td></tr>
                            <tr><td><strong>Registrar:</strong></td><td class="text-secondary">${whois.registrar || 'N/A'}</td></tr>
                            <tr><td><strong>Domain Age:</strong></td><td class="text-secondary">${whois.domain_age_days !== -1 ? whois.domain_age_days + ' days' : 'Unknown'}</td></tr>
                            <tr><td><strong>SSL Issuer:</strong></td><td class="text-secondary">${ssl.issuer || 'N/A'}</td></tr>
                            <tr><td><strong>SSL Active:</strong></td><td><span class="badge ${ssl.has_ssl ? 'bg-success' : 'bg-danger'}">${ssl.has_ssl ? 'Active' : 'Missing'}</span></td></tr>
                        </table>
                    </div>
                </div>

                <!-- Right: DNS Resolutions -->
                <div class="col-md-6">
                    <div class="p-3 bg-black bg-opacity-20 rounded border border-secondary border-opacity-10 h-100">
                        <strong class="text-info font-monospace d-block mb-2 small"><i class="fas fa-network-wired"></i> Authoritative DNS Maps</strong>
                        <div class="dns-records">
                            ${renderDnsRow("A Records (IP Resolution)", dns.A)}
                            ${renderDnsRow("MX Records (Mail Exchanger)", dns.MX)}
                            ${renderDnsRow("NS Records (Name Server)", dns.NS)}
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="mt-3 p-3 bg-black bg-opacity-30 rounded border border-secondary border-opacity-20 d-flex justify-content-between align-items-center">
                <span class="text-secondary small">Risk Level: <strong>${data.risk_score}%</strong> • Node Verdict: <strong>${data.prediction}</strong></span>
                <a href="/report/download/${data.scan_id}" class="btn-soc p-1 px-3 text-info"><i class="fas fa-file-pdf"></i> Download Audit Report</a>
            </div>
        </div>
    `;
}

// ----------------------------------------------------
// CHART GENERATOR (Using Chart.js)
// ----------------------------------------------------

function renderGaugeChart(riskScore) {
    const ctx = document.getElementById('riskGaugeCanvas');
    if (!ctx) return;

    if (riskGaugeChart) {
        riskGaugeChart.destroy();
    }

    const rest = 100 - riskScore;
    
    let mainColor = '#10b981'; // Green
    if (riskScore >= 70) mainColor = '#ef4444'; // Red
    else if (riskScore >= 35) mainColor = '#f59e0b'; // Yellow

    riskGaugeChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Risk', 'Safe'],
            datasets: [{
                data: [riskScore, rest],
                backgroundColor: [mainColor, '#1e293b'],
                borderWidth: 0
            }]
        },
        options: {
            rotation: -90,
            circumference: 180,
            cutout: '80%',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: { enabled: false }
            }
        }
    });
}
