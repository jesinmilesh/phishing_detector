/**
 * AI Shield SOC - Advanced Dashboard Logic
 * Design and interaction module for enterprise security operations center
 */

document.addEventListener('DOMContentLoaded', () => {
    // ----------------------------------------------------
    // 1. STATE & GLOBAL CONFIGURATION
    // ----------------------------------------------------
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
    
    // Table State
    let tableState = {
        search: '',
        prediction: 'all',
        sort: 'date_desc',
        page: 1,
        perPage: 10,
        totalPages: 1
    };

    // ----------------------------------------------------
    // 2. COLLAPSIBLE SIDEBAR LOGIC
    // ----------------------------------------------------
    const sidebar = document.getElementById('socSidebar');
    const sidebarToggleBtn = document.getElementById('sidebarToggle');
    const sidebarToggleInner = document.getElementById('sidebarToggleInner');
    const sidebarOverlay = document.getElementById('sidebarOverlay');
    const mainContent = document.querySelector('.soc-main-content');
    
    // Restore sidebar state from localStorage
    const isSidebarCollapsed = localStorage.getItem('soc_sidebar_collapsed') === 'true';
    if (isSidebarCollapsed && sidebar) {
        sidebar.classList.add('collapsed');
    }

    function toggleSidebar(e) {
        if (e) e.stopPropagation();
        if (!sidebar) return;
        
        if (window.innerWidth <= 992) {
            sidebar.classList.toggle('mobile-open');
            if (sidebarOverlay) {
                sidebarOverlay.classList.toggle('active');
            }
        } else {
            sidebar.classList.toggle('collapsed');
            localStorage.setItem('soc_sidebar_collapsed', sidebar.classList.contains('collapsed'));
        }
        
        // Trigger resize event to force Chart.js charts to redimension smoothly
        setTimeout(() => {
            window.dispatchEvent(new Event('resize'));
        }, 300);
    }

    if (sidebarToggleBtn) {
        sidebarToggleBtn.addEventListener('click', toggleSidebar);
    }
    if (sidebarToggleInner) {
        sidebarToggleInner.addEventListener('click', toggleSidebar);
    }

    if (sidebarOverlay) {
        sidebarOverlay.addEventListener('click', () => {
            if (sidebar) {
                sidebar.classList.remove('mobile-open');
            }
            sidebarOverlay.classList.remove('active');
        });
    }

    // ----------------------------------------------------
    // 3. SYSTEM CLOCK LOGIC
    // ----------------------------------------------------
    const clockElement = document.getElementById('socClock');
    if (clockElement) {
        const updateClock = () => {
            const now = new Date();
            const year = now.getUTCFullYear();
            const month = String(now.getUTCMonth() + 1).padStart(2, '0');
            const day = String(now.getUTCDate()).padStart(2, '0');
            const hours = String(now.getUTCHours()).padStart(2, '0');
            const minutes = String(now.getUTCMinutes()).padStart(2, '0');
            const seconds = String(now.getUTCSeconds()).padStart(2, '0');
            clockElement.textContent = `${year}-${month}-${day} ${hours}:${minutes}:${seconds} UTC`;
        };
        updateClock();
        setInterval(updateClock, 1000);
    }

    // ----------------------------------------------------
    // 4. CHARTS & ANALYTICS INITIALIZATION
    // ----------------------------------------------------
    initializeCharts();

    function initializeCharts() {
        const canvasBar = document.getElementById('dailyScansCanvas');
        if (!canvasBar) return;
        
        // Retrieve raw daily scans from DOM data attribute
        const dailyData = JSON.parse(canvasBar.dataset.dailyScans || '[]');
        
        // Reverse array to show chronological order (oldest to newest)
        const sortedData = [...dailyData].reverse();
        
        const labels = sortedData.map(d => {
            const date = new Date(d.date);
            return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
        });
        
        const legitimateData = sortedData.map(d => d.legitimate || 0);
        const suspiciousData = sortedData.map(d => d.suspicious || 0);
        const phishingData = sortedData.map(d => d.phishing || 0);

        // -- Chart 1: Daily Target Resolution (Bar) --
        new Chart(canvasBar, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Safe',
                        data: legitimateData,
                        backgroundColor: '#10b981',
                        borderRadius: 4
                    },
                    {
                        label: 'Suspicious',
                        data: suspiciousData,
                        backgroundColor: '#f59e0b',
                        borderRadius: 4
                    },
                    {
                        label: 'Phishing',
                        data: phishingData,
                        backgroundColor: '#ef4444',
                        borderRadius: 4
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        stacked: true,
                        grid: { display: false },
                        ticks: { color: '#9ca3af', font: { family: 'Inter', size: 10 } }
                    },
                    y: {
                        stacked: true,
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#9ca3af', font: { family: 'Inter', size: 10 } }
                    }
                },
                plugins: {
                    legend: {
                        position: 'top',
                        labels: { color: '#f9fafb', font: { family: 'Orbitron', size: 10 } }
                    },
                    tooltip: {
                        backgroundColor: '#0b0f19',
                        borderColor: 'rgba(0, 229, 255, 0.2)',
                        borderWidth: 1,
                        titleFont: { family: 'Orbitron' },
                        bodyFont: { family: 'Inter' }
                    }
                }
            }
        });
    }

    // ----------------------------------------------------
    // 5. NOTIFICATIONS CENTER LOGIC
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
                    // Update Badge
                    if (data.unread_count > 0) {
                        if (notifBadge) {
                            notifBadge.textContent = data.unread_count;
                            notifBadge.classList.remove('d-none');
                        }
                    } else {
                        if (notifBadge) notifBadge.classList.add('d-none');
                    }
                    
                    // Populate Notifications Dropdown
                    if (data.notifications.length === 0) {
                        notifList.innerHTML = '<div class="p-3 text-center text-muted">No security events found.</div>';
                    } else {
                        notifList.innerHTML = data.notifications.map(n => `
                            <div class="p-3 border-bottom border-secondary border-opacity-10 ${n.is_read ? '' : 'bg-info bg-opacity-5'}" id="notif-item-${n.id}" style="transition: all 0.2s;">
                                <div class="d-flex justify-content-between align-items-start mb-1">
                                    <strong class="text-white small d-flex align-items-center gap-2">
                                        <span class="d-inline-block rounded-circle bg-danger" style="width: 6px; height: 6px; display: ${n.is_read ? 'none' : 'inline-block'}"></span>
                                        ${n.title}
                                    </strong>
                                    <div class="d-flex gap-2">
                                        ${!n.is_read ? `<button class="btn btn-link p-0 text-info mark-read-btn" data-id="${n.id}" title="Mark read"><i class="fas fa-check"></i></button>` : ''}
                                        <button class="btn btn-link p-0 text-danger delete-notif-btn" data-id="${n.id}" title="Delete event"><i class="fas fa-trash-can"></i></button>
                                    </div>
                                </div>
                                <p class="text-secondary mb-1" style="font-size: 0.75rem; line-height:1.3">${n.message}</p>
                                <span class="text-muted" style="font-size: 0.65rem;">${n.created_at}</span>
                            </div>
                        `).join('');
                    }
                }
            })
            .catch(err => console.error("Error loading notifications:", err));
    }
    
    // Notification Actions Event Delegation
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
                })
                .then(res => res.json())
                .then(data => {
                    if (data.success) {
                        fetchNotifications();
                        showToast("Alert marked as read.", "success");
                    }
                });
            }
            
            if (deleteBtn) {
                e.stopPropagation();
                const notifId = deleteBtn.dataset.id;
                fetch(`/notifications/delete/${notifId}`, {
                    method: 'DELETE',
                    headers: { 'X-CSRFToken': csrfToken }
                })
                .then(res => res.json())
                .then(data => {
                    if (data.success) {
                        fetchNotifications();
                        showToast("Notification deleted.", "info");
                    }
                });
            }
        });
    }

    if (markAllReadBtn) {
        markAllReadBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            fetch('/notifications/read-all', {
                method: 'POST',
                headers: { 'X-CSRFToken': csrfToken }
            })
            .then(() => {
                fetchNotifications();
                showToast("All security alerts marked as read.", "success");
            });
        });
    }
    
    // Initial fetch & poll notifications every 30 seconds
    fetchNotifications();
    setInterval(fetchNotifications, 30000);

    // ----------------------------------------------------
    // 6. INTERACTIVE SCANS TABLE LOGIC (AJAX)
    // ----------------------------------------------------
    const tableBody = document.getElementById('scansTableBody');
    const searchInput = document.getElementById('tableSearchInput');
    const filterPrediction = document.getElementById('tableFilterPrediction');
    const prevPageBtn = document.getElementById('prevPageBtn');
    const nextPageBtn = document.getElementById('nextPageBtn');
    const pageIndicator = document.getElementById('pageIndicator');
    const sortHeaders = document.querySelectorAll('.table-soc th.sortable');

    function fetchTableData() {
        if (!tableBody) return;
        tableBody.innerHTML = `<tr><td colspan="7" class="text-center text-muted py-4"><i class="fas fa-spinner fa-spin me-2"></i> Querying threat history database...</td></tr>`;
        
        const params = new URLSearchParams({
            format: 'json',
            search: tableState.search,
            prediction: tableState.prediction,
            sort: tableState.sort,
            page: tableState.page,
            per_page: tableState.perPage
        });

        fetch(`/history?${params.toString()}`)
            .then(res => res.json())
            .then(data => {
                renderTable(data.scans || []);
                updatePaginationControls(data);
            })
            .catch(err => {
                console.error("Error loading scan history:", err);
                tableBody.innerHTML = `<tr><td colspan="7" class="text-center text-danger py-4"><i class="fas fa-triangle-exclamation me-2"></i> Failed to pull threat feeds. Please try again.</td></tr>`;
            });
    }

    function renderTable(scans) {
        if (!tableBody) return;
        if (scans.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="7" class="text-center text-muted py-4">No security threats or scanned indicators match the current parameters.</td></tr>`;
            return;
        }

        tableBody.innerHTML = scans.map(scan => {
            let badgeClass = 'badge-soc-success';
            if (scan.prediction === 'Phishing') badgeClass = 'badge-soc-danger';
            else if (scan.prediction === 'Suspicious') badgeClass = 'badge-soc-warning';

            const formattedTime = scan.scan_time ? scan.scan_time.substring(0, 19).replace('T', ' ') : 'N/A';
            const displayUrl = scan.url.length > 50 ? `${scan.url.substring(0, 47)}...` : scan.url;

            // Details json analysis check
            const category = scan.details?.features?.dns?.domain_age_days ? 'Domain Age Check' : 'Heuristic Score';

            return `
                <tr>
                    <td><code class="text-info text-break" style="font-size:0.8rem">${escapeHtml(displayUrl)}</code></td>
                    <td><span class="badge-soc ${badgeClass}">${scan.prediction}</span></td>
                    <td class="fw-bold text-white">${scan.risk_score}%</td>
                    <td><span class="text-secondary small">${category}</span></td>
                    <td class="text-secondary small">${formattedTime}</td>
                    <td>
                        <span class="badge bg-opacity-10 bg-success text-success border border-success px-2 py-1 small">RESOLVED</span>
                    </td>
                    <td>
                        <a href="/report/download/${scan.id}" class="btn-soc p-1 px-2 text-info" title="Download Audit Report"><i class="fas fa-file-pdf"></i></a>
                    </td>
                </tr>
            `;
        }).join('');
    }

    function updatePaginationControls(data) {
        if (!pageIndicator) return;
        tableState.totalPages = data.total_pages || 1;
        pageIndicator.textContent = `Page ${data.current_page} of ${tableState.totalPages}`;
        
        if (prevPageBtn) prevPageBtn.disabled = data.current_page <= 1;
        if (nextPageBtn) nextPageBtn.disabled = data.current_page >= tableState.totalPages;
    }

    // Event Handlers for Pagination
    if (prevPageBtn) {
        prevPageBtn.addEventListener('click', () => {
            if (tableState.page > 1) {
                tableState.page--;
                fetchTableData();
            }
        });
    }

    if (nextPageBtn) {
        nextPageBtn.addEventListener('click', () => {
            if (tableState.page < tableState.totalPages) {
                tableState.page++;
                fetchTableData();
            }
        });
    }

    // Debounced Search
    let searchTimeout;
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            clearTimeout(searchTimeout);
            tableState.search = e.target.value.trim();
            tableState.page = 1; // reset page
            searchTimeout = setTimeout(fetchTableData, 300);
        });
    }

    // Filter Change
    if (filterPrediction) {
        filterPrediction.addEventListener('change', (e) => {
            tableState.prediction = e.target.value;
            tableState.page = 1;
            fetchTableData();
        });
    }

    // Sorting Headers
    sortHeaders.forEach(header => {
        header.addEventListener('click', () => {
            const field = header.dataset.sort;
            let currentDir = 'desc';
            
            if (tableState.sort.startsWith(field)) {
                currentDir = tableState.sort.endsWith('desc') ? 'asc' : 'desc';
            }
            
            tableState.sort = `${field}_${currentDir}`;
            
            // Update icons
            sortHeaders.forEach(h => {
                const icon = h.querySelector('i');
                if (icon) {
                    icon.className = 'fas fa-sort';
                }
            });
            
            const curIcon = header.querySelector('i');
            if (curIcon) {
                curIcon.className = `fas fa-sort-${currentDir === 'desc' ? 'down' : 'up'}`;
            }

            tableState.page = 1;
            fetchTableData();
        });
    });

    // Initial table load
    fetchTableData();

    // ----------------------------------------------------
    // 7. CSV EXPORT LOGIC
    // ----------------------------------------------------
    const exportBtn = document.getElementById('exportCsvBtn');
    if (exportBtn) {
        exportBtn.addEventListener('click', () => {
            const params = new URLSearchParams({
                format: 'json',
                search: tableState.search,
                prediction: tableState.prediction,
                sort: tableState.sort,
                page: 1,
                per_page: 50 // export larger chunk
            });

            fetch(`/history?${params.toString()}`)
                .then(res => res.json())
                .then(data => {
                    const scans = data.scans || [];
                    if (scans.length === 0) {
                        showToast("No data to export.", "warning");
                        return;
                    }
                    
                    // Convert to CSV
                    const headers = ['URL', 'Verdict', 'Risk Score', 'Scan Time', 'Status'];
                    const rows = scans.map(s => [
                        `"${s.url.replace(/"/g, '""')}"`,
                        s.prediction,
                        `${s.risk_score}%`,
                        s.scan_time,
                        'Resolved'
                    ]);
                    
                    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
                    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
                    const url = URL.createObjectURL(blob);
                    
                    const link = document.createElement("a");
                    link.setAttribute("href", url);
                    link.setAttribute("download", `ai_shield_threat_report_${new Date().toISOString().slice(0,10)}.csv`);
                    document.body.appendChild(link);
                    link.click();
                    document.body.removeChild(link);
                    
                    showToast("Threat log CSV export successfully compiled.", "success");
                })
                .catch(() => showToast("Export failed.", "danger"));
        });
    }

    // ----------------------------------------------------
    // 8. TOAST MESSAGES UTILITY
    // ----------------------------------------------------
    function showToast(message, type = 'info') {
        let container = document.getElementById('socToastContainer');
        if (!container) {
            container = document.createElement('div');
            container.id = 'socToastContainer';
            container.className = 'soc-toast-container';
            document.body.appendChild(container);
        }

        const toast = document.createElement('div');
        toast.className = `soc-toast toast-${type}`;
        
        let iconClass = 'fa-info-circle text-info';
        if (type === 'success') iconClass = 'fa-circle-check text-success';
        else if (type === 'danger') iconClass = 'fa-triangle-exclamation text-danger';
        else if (type === 'warning') iconClass = 'fa-circle-exclamation text-warning';

        toast.innerHTML = `
            <i class="fas ${iconClass}"></i>
            <span>${escapeHtml(message)}</span>
        `;

        container.appendChild(toast);
        
        // Remove toast after 4s
        setTimeout(() => {
            toast.style.animation = 'slideInToast 0.3s reverse forwards';
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    }

    // Helper to escape HTML characters
    function escapeHtml(str) {
        return str.replace(/[&<>'"]/g, 
            tag => ({
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                "'": '&#39;',
                '"': '&quot;'
            }[tag] || tag)
        );
    }

    // ----------------------------------------------------
    // 9. QUICK SCAN HANDLER
    // ----------------------------------------------------
    const quickScanForm = document.getElementById('quickScanForm');
    if (quickScanForm) {
        quickScanForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const input = document.getElementById('quickScanInput');
            const submitBtn = document.getElementById('quickScanSubmitBtn');
            const loader = document.getElementById('quickScanLoading');
            const resultPanel = document.getElementById('quickScanResult');
            
            let urlVal = input.value.trim();
            if (!urlVal) return;
            
            if (!urlVal.startsWith('http://') && !urlVal.startsWith('https://')) {
                urlVal = 'http://' + urlVal;
            }
            
            submitBtn.disabled = true;
            loader.classList.remove('d-none');
            resultPanel.classList.add('d-none');
            
            try {
                const formData = new FormData();
                formData.append('url', urlVal);
                
                const response = await fetch('/scan/url', {
                    method: 'POST',
                    headers: { 'X-CSRFToken': csrfToken },
                    body: formData
                });
                
                const res = await response.json();
                if (res.success) {
                    const data = res.data;
                    document.getElementById('quickScanId').textContent = `Scan ID: SEC-${data.scan_id}`;
                    document.getElementById('quickScanUrlVal').textContent = data.url;
                    document.getElementById('quickScanRiskVal').textContent = `${data.risk_score}%`;
                    
                    const reportLink = document.getElementById('quickScanReportLink');
                    reportLink.href = `/report/download/${data.scan_id}`;
                    
                    const badge = document.getElementById('quickScanVerdictBadge');
                    badge.textContent = data.prediction.toUpperCase();
                    
                    badge.className = 'badge';
                    if (data.prediction === 'Phishing') {
                        badge.classList.add('bg-danger');
                    } else if (data.prediction === 'Suspicious') {
                        badge.classList.add('bg-warning');
                    } else {
                        badge.classList.add('bg-success');
                    }
                    
                    resultPanel.classList.remove('d-none');
                    showToast("Scan completed successfully", "success");
                    
                    if (typeof fetchTableData === 'function') {
                        fetchTableData();
                    }
                } else {
                    showToast(res.error || "Scan failed", "danger");
                }
            } catch (err) {
                showToast("Connection to security engine lost.", "danger");
            } finally {
                submitBtn.disabled = false;
                loader.classList.add('d-none');
            }
        });
    }
});
