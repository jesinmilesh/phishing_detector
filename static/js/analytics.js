// static/js/analytics.js
document.addEventListener("DOMContentLoaded", function() {
    
    // --- SIDEBAR TOGGLE MECHANICS ---
    const sidebar = document.getElementById("socSidebar");
    const overlay = document.getElementById("sidebarOverlay");
    const toggleMobileBtn = document.getElementById("sidebarToggleMobile");
    const toggleInnerBtn = document.getElementById("sidebarToggleInner");

    if (toggleMobileBtn && sidebar) {
        toggleMobileBtn.addEventListener("click", () => {
            sidebar.classList.add("active");
            if (overlay) overlay.classList.add("active");
        });
    }

    if (toggleInnerBtn && sidebar) {
        toggleInnerBtn.addEventListener("click", () => {
            sidebar.classList.remove("active");
            if (overlay) overlay.classList.remove("active");
        });
    }

    if (overlay && sidebar) {
        overlay.addEventListener("click", () => {
            sidebar.classList.remove("active");
            overlay.classList.remove("active");
        });
    }

    // --- CHART INITIALIZATION ---
    // Extract datasets from canvas data attributes
    const trendsCanvas = document.getElementById("threatTrendsChart");
    const distCanvas = document.getElementById("riskDistributionChart");
    const diagCanvas = document.getElementById("modelDiagnosticsChart");

    if (!trendsCanvas || !distCanvas || !diagCanvas) return;

    const dailyTrends = JSON.parse(trendsCanvas.getAttribute("data-trends") || "[]");
    
    const dates = dailyTrends.map(t => t.date);
    const totalVolume = dailyTrends.map(t => t.count);
    const phishingCounts = dailyTrends.map(t => t.phishing);
    const suspiciousCounts = dailyTrends.map(t => t.suspicious);
    const legitimateCounts = dailyTrends.map(t => t.legitimate);

    // 1. Threat Trends Chart (Stacked Line/Area)
    new Chart(trendsCanvas.getContext("2d"), {
        type: 'line',
        data: {
            labels: dates,
            datasets: [
                {
                    label: 'Phishing',
                    data: phishingCounts,
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    fill: true,
                    tension: 0.35,
                    borderWidth: 2
                },
                {
                    label: 'Suspicious',
                    data: suspiciousCounts,
                    borderColor: '#f59e0b',
                    backgroundColor: 'rgba(245, 158, 11, 0.1)',
                    fill: true,
                    tension: 0.35,
                    borderWidth: 2
                },
                {
                    label: 'Legitimate',
                    data: legitimateCounts,
                    borderColor: '#22c55e',
                    backgroundColor: 'rgba(34, 197, 94, 0.05)',
                    fill: true,
                    tension: 0.35,
                    borderWidth: 2
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: { color: '#cbd5e1' }
                }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(255,255,255,0.05)' },
                    ticks: { color: '#94a3b8' }
                },
                y: {
                    grid: { color: 'rgba(255,255,255,0.05)' },
                    ticks: { color: '#94a3b8' }
                }
            }
        }
    });

    // 2. Risk Distribution (Doughnut)
    const phishing = parseFloat(distCanvas.getAttribute("data-phishing") || "0");
    const suspicious = parseFloat(distCanvas.getAttribute("data-suspicious") || "0");
    const legitimate = parseFloat(distCanvas.getAttribute("data-legitimate") || "0");

    new Chart(distCanvas.getContext("2d"), {
        type: 'doughnut',
        data: {
            labels: ['Phishing', 'Suspicious', 'Legitimate'],
            datasets: [{
                data: [phishing, suspicious, legitimate],
                backgroundColor: ['#ef4444', '#f59e0b', '#22c55e'],
                borderWidth: 1,
                borderColor: '#1e293b'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#cbd5e1' }
                }
            }
        }
    });

    // 3. Scan Volume (Bar Chart)
    const volumeCanvas = document.getElementById("scanVolumeChart");
    if (volumeCanvas) {
        new Chart(volumeCanvas.getContext("2d"), {
            type: 'bar',
            data: {
                labels: dates,
                datasets: [{
                    label: 'Daily Scan Ingestion Count',
                    data: totalVolume,
                    backgroundColor: 'rgba(14, 165, 233, 0.45)',
                    borderColor: '#0ea5e9',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(255,255,255,0.03)' },
                        ticks: { color: '#94a3b8' }
                    },
                    y: {
                        grid: { color: 'rgba(255,255,255,0.03)' },
                        ticks: { color: '#94a3b8' }
                    }
                }
            }
        });
    }

    // 4. Model Diagnostics Chart (Semi-doughnut gauge for accuracy)
    const accuracy = parseFloat(diagCanvas.getAttribute("data-accuracy") || "94.2");
    new Chart(diagCanvas.getContext("2d"), {
        type: 'doughnut',
        data: {
            labels: ['Model Accuracy', 'Remaining Margin'],
            datasets: [{
                data: [accuracy, 100 - accuracy],
                backgroundColor: ['#14b8a6', 'rgba(255,255,255,0.05)'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            rotation: -90,
            circumference: 180,
            cutout: '80%',
            plugins: {
                legend: { display: false }
            }
        }
    });
});
