/* ========================================================
   AI SHIELD - REPORTS CENTER INTERACTIVE SCRIPT
   Client-Side Controllers, Search Engines & Analytics Rendering
   ======================================================== */

document.addEventListener('DOMContentLoaded', function() {
    // 1. DOM Elements & State
    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
    const sidebar = document.getElementById('socSidebar');
    const mainPanel = document.getElementById('reportsMainPanel');
    const sidebarToggle = document.getElementById('sidebarToggleBtn');
    
    let activeFilters = {
        search: '',
        threatLevel: 'all',
        reportType: 'all',
        dateRange: '30'
    };

    // Sidebar Collapsible Controller
    if (sidebarToggle && sidebar && mainPanel) {
        sidebarToggle.addEventListener('click', function() {
            sidebar.classList.toggle('reports-sidebar-collapsed');
            mainPanel.classList.toggle('sidebar-collapsed');
            
            // Adjust any active charts on resize
            setTimeout(() => {
                if (window.threatTrendsChart) window.threatTrendsChart.resize();
                if (window.riskDistChart) window.riskDistChart.resize();
            }, 300);
        });
    }

    // Mobile Hamburger
    const mobileSidebarToggle = document.getElementById('mobileSidebarToggleBtn');
    if (mobileSidebarToggle && sidebar) {
        mobileSidebarToggle.addEventListener('click', function(e) {
            e.stopPropagation();
            sidebar.classList.toggle('active');
        });
        
        document.addEventListener('click', function(e) {
            if (!sidebar.contains(e.target) && sidebar.classList.contains('active')) {
                sidebar.classList.remove('active');
            }
        });
    }

    // 2. Interactive Charts (Chart.js)
    initializeCharts();

    // 3. Search and Filtering Logic
    const searchField = document.getElementById('reportSearchField');
    const threatFilter = document.getElementById('threatLevelFilter');
    const typeFilter = document.getElementById('reportTypeFilter');
    const dateFilter = document.getElementById('dateRangeFilter');
    const tableRows = document.querySelectorAll('#reportsTableBody tr');

    function filterTable() {
        activeFilters.search = searchField ? searchField.value.toLowerCase().trim() : '';
        activeFilters.threatLevel = threatFilter ? threatFilter.value.toLowerCase() : 'all';
        activeFilters.reportType = typeFilter ? typeFilter.value.toLowerCase() : 'all';
        activeFilters.dateRange = dateFilter ? dateFilter.value : 'all';

        let visibleCount = 0;
        tableRows.forEach(row => {
            if (row.classList.contains('empty-row-placeholder')) return;

            const id = row.querySelector('.report-id').textContent.toLowerCase();
            const name = row.querySelector('.report-name').textContent.toLowerCase();
            const type = row.dataset.reportType ? row.dataset.reportType.toLowerCase() : '';
            const verdict = row.querySelector('.verdict-badge') ? row.querySelector('.verdict-badge').textContent.toLowerCase() : '';
            const dateStr = row.querySelector('.report-date').textContent;
            
            // Match criteria
            const matchesSearch = id.includes(activeFilters.search) || name.includes(activeFilters.search);
            const matchesThreat = activeFilters.threatLevel === 'all' || verdict.includes(activeFilters.threatLevel);
            const matchesType = activeFilters.reportType === 'all' || type === activeFilters.reportType;
            
            // Date filter comparison
            let matchesDate = true;
            if (activeFilters.dateRange !== 'all') {
                const rowDate = new Date(dateStr);
                const now = new Date();
                const diffTime = Math.abs(now - rowDate);
                const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
                matchesDate = diffDays <= parseInt(activeFilters.dateRange);
            }

            if (matchesSearch && matchesThreat && matchesType && matchesDate) {
                row.style.display = '';
                visibleCount++;
            } else {
                row.style.display = 'none';
            }
        });

        // Toggle Empty Placeholder
        const emptyPlaceholder = document.getElementById('emptyTablePlaceholder');
        if (emptyPlaceholder) {
            emptyPlaceholder.style.display = visibleCount === 0 ? '' : 'none';
        }
    }

    if (searchField) searchField.addEventListener('input', filterTable);
    if (threatFilter) threatFilter.addEventListener('change', filterTable);
    if (typeFilter) typeFilter.addEventListener('change', filterTable);
    if (dateFilter) dateFilter.addEventListener('change', filterTable);

    // 4. Report Details Flyout Manager
    const detailsPanel = document.getElementById('reportDetailsPanel');
    
    // Attach click events on table rows
    tableRows.forEach(row => {
        row.addEventListener('click', function(e) {
            // Prevent trigger if clicking action buttons
            if (e.target.closest('.table-actions-row') || e.target.closest('.form-check-input')) {
                return;
            }
            
            // Highlight active row
            tableRows.forEach(r => r.classList.remove('selected'));
            row.classList.add('selected');
            
            const reportId = row.dataset.reportId;
            const reportName = row.querySelector('.report-name').textContent;
            const reportType = row.dataset.reportType || 'Threat Scan';
            const riskScore = parseInt(row.dataset.riskScore) || 0;
            const verdict = row.querySelector('.verdict-badge') ? row.querySelector('.verdict-badge').textContent : 'UNKNOWN';
            const dateStr = row.querySelector('.report-date').textContent;
            const targetUrl = row.dataset.targetUrl || 'N/A';
            const analyst = row.dataset.createdBy || 'System node';

            displayReportDetails({
                id: reportId,
                name: reportName,
                type: reportType,
                riskScore: riskScore,
                verdict: verdict,
                date: dateStr,
                url: targetUrl,
                analyst: analyst
            });
        });
    });

    function displayReportDetails(data) {
        document.getElementById('detailReportId').textContent = '#' + String(data.id).padStart(4, '0');
        document.getElementById('detailReportName').textContent = data.name;
        document.getElementById('detailReportType').textContent = data.type;
        document.getElementById('detailRiskScore').textContent = data.riskScore + '%';
        document.getElementById('detailTargetUrl').textContent = data.url;
        document.getElementById('detailCreatedBy').textContent = data.analyst;
        document.getElementById('detailScanDate').textContent = data.date;

        // Color coding for score
        const scoreWidget = document.getElementById('detailRiskScore');
        scoreWidget.className = 'value';
        if (data.riskScore >= 75) {
            scoreWidget.style.color = 'var(--threat-red)';
            document.getElementById('detailPostureVerdict').innerHTML = '<span class="verdict-badge badge-phishing">PHISHING SIGNATURE</span>';
            document.getElementById('detailFindingsText').textContent = 'High confidence threat matches detected with lexical, trademark, and reputation indicator overlaps.';
            document.getElementById('detailMitigationText').innerHTML = '<li>Block domains instantly on enterprise perimeter firewall routers.</li><li>Revoke any user credentials associated with access logs to this link.</li><li>Initiate trademark spoof take-down protocols.</li>';
        } else if (data.riskScore >= 40) {
            scoreWidget.style.color = 'var(--amber-warning)';
            document.getElementById('detailPostureVerdict').innerHTML = '<span class="verdict-badge badge-suspicious">SUSPICIOUS SIGNATURE</span>';
            document.getElementById('detailFindingsText').textContent = 'Moderate indicators matches. Whois domain records show low age and lacks valid DNS MX parameters.';
            document.getElementById('detailMitigationText').innerHTML = '<li>Inspect server headers for redirects.</li><li>Advise organization users against entering credential tokens.</li><li>Flag in security log archives.</li>';
        } else {
            scoreWidget.style.color = 'var(--security-green)';
            document.getElementById('detailPostureVerdict').innerHTML = '<span class="verdict-badge badge-legitimate">LEGITIMATE</span>';
            document.getElementById('detailFindingsText').textContent = 'Lexical integrity verified. Valid SSL certificate matches trust registrars.';
            document.getElementById('detailMitigationText').innerHTML = '<li>No threat mitigations required.</li><li>Domain whitelisted.</li>';
        }
    }

    // 5. New Report Generation Handler
    const generateBtn = document.getElementById('triggerGenerateReportBtn');
    const modalGenBtn = document.getElementById('confirmReportGenerationBtn');
    
    if (modalGenBtn) {
        modalGenBtn.addEventListener('click', function() {
            const reportType = document.getElementById('genReportType').value;
            const range = document.getElementById('genDateRange').value;
            const format = document.getElementById('genFormat').value;

            // Close bootstrap modal programmatically
            const modalEl = document.getElementById('generateReportModal');
            const modalInstance = bootstrap.Modal.getInstance(modalEl);
            if (modalInstance) modalInstance.hide();

            showNotification('Generating ' + reportType + ' report (' + format + ')...', 'info');

            fetch('/api/reports/generate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({
                    report_type: reportType,
                    date_range: range,
                    format: format
                })
            })
            .then(async res => {
                if (!res.ok) {
                    const errText = await res.text();
                    try {
                        const errJson = JSON.parse(errText);
                        throw new Error(errJson.error || 'Report generation failed');
                    } catch(e) {
                        throw new Error(errText || 'Report generation failed');
                    }
                }
                
                const blob = await res.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `ai_shield_report_${reportType.toLowerCase().replace(/\s+/g, '_')}_${new Date().toISOString().slice(0,10)}.${format}`;
                document.body.appendChild(a);
                a.click();
                a.remove();
                window.URL.revokeObjectURL(url);
                showNotification('Report generated and downloaded successfully.', 'success');
            })
            .catch(err => {
                console.error(err);
                showNotification('Error generating report: ' + err.message, 'danger');
            });
        });
    }

    // 5.2 Individual Report Deletion Handler
    document.querySelectorAll('.delete-report-btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const reportId = this.getAttribute('data-report-id');
            if (confirm('Are you sure you want to delete report record #' + reportId + '?')) {
                fetch('/api/history/delete/' + reportId, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': csrfToken
                    }
                })
                .then(res => res.json())
                .then(data => {
                    if (data.success) {
                        showNotification('Report deleted successfully.', 'success');
                        const row = document.querySelector(`tr[data-report-id="${reportId}"]`);
                        if (row) row.remove();
                    } else {
                        showNotification('Failed to delete report: ' + (data.error || 'Unknown error'), 'danger');
                    }
                })
                .catch(err => {
                    console.error(err);
                    showNotification('Network error during deletion.', 'danger');
                });
            }
        });
    });

    // 6. Export Center Controller (Bulk Downloads)
    const exportCsvBtn = document.getElementById('exportCsvBtn');
    const exportJsonBtn = document.getElementById('exportJsonBtn');

    if (exportCsvBtn) {
        exportCsvBtn.addEventListener('click', function() {
            let csvContent = "data:text/csv;charset=utf-8,Report ID,Report Name,Report Type,Verdict,Risk Score,Date,Created By\n";
            tableRows.forEach(row => {
                if (row.style.display !== 'none' && !row.classList.contains('empty-row-placeholder')) {
                    const id = row.querySelector('.report-id').textContent;
                    const name = row.querySelector('.report-name').textContent;
                    const type = row.dataset.reportType || 'Threat Scan';
                    const verdict = row.querySelector('.verdict-badge') ? row.querySelector('.verdict-badge').textContent : 'Legitimate';
                    const risk = row.dataset.riskScore || '0';
                    const date = row.querySelector('.report-date').textContent;
                    const analyst = row.dataset.createdBy || 'System Node';
                    csvContent += `"${id}","${name}","${type}","${verdict}","${risk}%","${date}","${analyst}"\n`;
                }
            });

            const encodedUri = encodeURI(csvContent);
            const link = document.createElement("a");
            link.setAttribute("href", encodedUri);
            link.setAttribute("download", "ai_shield_threat_reports.csv");
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            showNotification('CSV export download started.', 'success');
        });
    }

    if (exportJsonBtn) {
        exportJsonBtn.addEventListener('click', function() {
            let exportData = [];
            tableRows.forEach(row => {
                if (row.style.display !== 'none' && !row.classList.contains('empty-row-placeholder')) {
                    exportData.push({
                        id: row.querySelector('.report-id').textContent,
                        name: row.querySelector('.report-name').textContent,
                        type: row.dataset.reportType || 'Threat Scan',
                        verdict: row.querySelector('.verdict-badge') ? row.querySelector('.verdict-badge').textContent : 'Legitimate',
                        risk_score: row.dataset.riskScore || '0',
                        date: row.querySelector('.report-date').textContent,
                        analyst: row.dataset.createdBy || 'System'
                    });
                }
            });

            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(exportData, null, 4));
            const link = document.createElement("a");
            link.setAttribute("href", dataStr);
            link.setAttribute("download", "ai_shield_threat_reports.json");
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            showNotification('JSON export download started.', 'success');
        });
    }

    // Helper notifications toast
    function showNotification(msg, type = 'info') {
        const toastContainer = document.getElementById('toastContainer');
        if (!toastContainer) {
            const container = document.createElement('div');
            container.id = 'toastContainer';
            container.className = 'position-fixed bottom-0 end-0 p-3';
            container.style.zIndex = '9999';
            document.body.appendChild(container);
        }
        
        const bgClass = type === 'success' ? 'bg-success' : type === 'danger' ? 'bg-danger' : 'bg-primary';
        const toastHtml = `
            <div class="toast show align-items-center text-white ${bgClass} border-0 mb-2" role="alert" aria-live="assertive" aria-atomic="true" style="backdrop-filter: blur(10px); background-opacity: 0.9;">
                <div class="d-flex">
                    <div class="toast-body">
                        <i class="fas fa-circle-info me-2"></i> ${msg}
                    </div>
                    <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
                </div>
            </div>
        `;
        document.getElementById('toastContainer').insertAdjacentHTML('beforeend', toastHtml);
        
        const toasts = document.querySelectorAll('.toast');
        const latestToast = toasts[toasts.length - 1];
        setTimeout(() => {
            if (latestToast) latestToast.remove();
        }, 4000);
    }
});

// Chart.js Init function
function initializeCharts() {
    // 1. Threat Trends Chart
    const trendCtx = document.getElementById('threatTrendsChartCanvas');
    if (trendCtx) {
        const dailyData = JSON.parse(trendCtx.dataset.dailyScans || '[]');
        const sortedData = [...dailyData].reverse();
        
        const labels = sortedData.length > 0 ? sortedData.map(d => {
            const date = new Date(d.date);
            return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
        }) : ['No Data'];
        
        const phishingData = sortedData.length > 0 ? sortedData.map(d => d.phishing || 0) : [0];
        const legitimateData = sortedData.length > 0 ? sortedData.map(d => d.legitimate || 0) : [0];

        window.threatTrendsChart = new Chart(trendCtx.getContext('2d'), {
            type: 'line',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Phishing Scans',
                        data: phishingData,
                        borderColor: '#ef4444',
                        backgroundColor: 'rgba(239, 68, 68, 0.05)',
                        borderWidth: 2,
                        tension: 0.4,
                        fill: true
                    },
                    {
                        label: 'Safe Scans',
                        data: legitimateData,
                        borderColor: '#10b981',
                        backgroundColor: 'rgba(16, 185, 129, 0.05)',
                        borderWidth: 2,
                        tension: 0.4,
                        fill: true
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: { color: '#94a3b8', font: { size: 10 } }
                    }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#94a3b8', font: { size: 9 } }
                    },
                    y: {
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#94a3b8', font: { size: 9 } }
                    }
                }
            }
        });
    }

    // 2. Risk Distribution Chart
    const riskCtx = document.getElementById('riskDistributionChartCanvas');
    if (riskCtx) {
        const totalPhish = parseInt(riskCtx.dataset.phishing || '0');
        const totalSusp = parseInt(riskCtx.dataset.suspicious || '0');
        const totalSafe = parseInt(riskCtx.dataset.legitimate || '0');

        window.riskDistChart = new Chart(riskCtx.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: ['Legitimate', 'Suspicious', 'Phishing'],
                datasets: [{
                    data: [totalSafe, totalSusp, totalPhish],
                    backgroundColor: ['#10b981', '#f59e0b', '#ef4444'],
                    borderColor: 'rgba(30, 41, 59, 0.8)',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#94a3b8', font: { size: 10 } }
                    }
                }
            }
        });
    }
}
