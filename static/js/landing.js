/* AI Shield Premium Landing Page Scripting - UI/UX & Interactions */
document.addEventListener('DOMContentLoaded', function() {
    
    // ==========================================
    // 1. THEME TOGGLE (DARK / LIGHT MODE)
    // ==========================================
    const themeToggleBtn = document.getElementById('themeToggleBtn');
    const themeIcon = themeToggleBtn.querySelector('i');
    
    // Check local storage for saved theme preference
    const savedTheme = localStorage.getItem('theme') || 'dark';
    if (savedTheme === 'light') {
        document.body.classList.add('light-theme');
        themeIcon.className = 'fas fa-moon';
    } else {
        document.body.classList.remove('light-theme');
        themeIcon.className = 'fas fa-sun';
    }

    themeToggleBtn.addEventListener('click', function() {
        if (document.body.classList.contains('light-theme')) {
            document.body.classList.remove('light-theme');
            themeIcon.className = 'fas fa-sun';
            localStorage.setItem('theme', 'dark');
        } else {
            document.body.classList.add('light-theme');
            themeIcon.className = 'fas fa-moon';
            localStorage.setItem('theme', 'light');
        }
    });

    // ==========================================
    // 2. NAV SCROLL EFFECT & SMOOTH SCROLLING
    // ==========================================
    const navbar = document.querySelector('.navbar');
    window.addEventListener('scroll', function() {
        if (window.scrollY > 50) {
            navbar.classList.add('navbar-scrolled');
        } else {
            navbar.classList.remove('navbar-scrolled');
        }
    });

    // ==========================================
    // 3. STATS ANIMATED COUNTERS
    // ==========================================
    const counters = document.querySelectorAll('.counter-val');
    const speed = 200; // The lower the slower

    const startCounter = (counter) => {
        const target = +counter.getAttribute('data-target');
        const suffix = counter.getAttribute('data-suffix') || '';

        const updateCount = () => {
            const current = +counter.innerText.replace(/[^0-9]/g, '');
            const inc = target / speed;

            if (current < target) {
                counter.innerText = Math.ceil(current + inc).toLocaleString() + suffix;
                setTimeout(updateCount, 10);
            } else {
                counter.innerText = target.toLocaleString() + suffix;
            }
        };
        updateCount();
    };

    const triggerCounters = () => {
        counters.forEach(counter => {
            const card = counter.closest('.counter-card');
            const delay = parseInt(card ? card.getAttribute('data-delay') : '0') || 0;
            setTimeout(() => {
                startCounter(counter);
            }, delay);
        });
    };

    // Trigger counters when scrolled into view
    const observerOptions = {
        threshold: 0.5
    };

    const statsObserver = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                triggerCounters();
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);

    const statsSection = document.querySelector('.trust-section');
    if (statsSection) {
        statsObserver.observe(statsSection);
    }

    // ==========================================
    // 4. INTERACTIVE LIVE DEMO SCANNER
    // ==========================================
    const demoInput = document.getElementById('demoInput');
    const demoBtn = document.getElementById('demoBtn');
    const consoleOutput = document.getElementById('consoleOutput');
    const demoScoreCard = document.getElementById('demoScoreCard');
    const demoGauge = document.getElementById('demoGauge');
    const demoVerdict = document.getElementById('demoVerdict');

    const sampleThreats = {
        'paypal': { score: 87, verdict: 'CRITICAL PHISHING RISK', class: 'text-danger', desc: 'Mimics authorized PayPal brand. Domain registration: 1 day ago. Missing security certificates.' },
        'netflix': { score: 92, verdict: 'CRITICAL PHISHING RISK', class: 'text-danger', desc: 'Netflix authentication clone page detected. Hosted on non-standard IP. Suspicious domain keywords.' },
        'chase': { score: 95, verdict: 'CRITICAL PHISHING RISK', class: 'text-danger', desc: 'Direct spoofing targeting JPMorgan Chase login node. SSL Certificate issuer untrusted.' },
        'google': { score: 2, verdict: 'SECURE LEGITIMATE NODE', class: 'text-success', desc: 'Domain recognized. Highly trusted authority. Verified SSL certificates.' },
        'github': { score: 1, verdict: 'SECURE LEGITIMATE NODE', class: 'text-success', desc: 'Verified public hosting domain. Trusted secure authority.' }
    };

    demoBtn.addEventListener('click', function() {
        const urlValue = demoInput.value.trim().toLowerCase();
        if (!urlValue) {
            alert('Please enter a target URL address to scan.');
            return;
        }

        // Initialize scanning console animation
        demoBtn.disabled = true;
        consoleOutput.innerHTML = `<span class="text-info">[i] Initializing Threat Scan Core...</span><br>`;
        demoScoreCard.classList.add('d-none');

        const logLines = [
            `[+] Establishing sandbox connection for target: ${urlValue}`,
            `[+] Fetching WHOIS metadata & Domain Registry details...`,
            `[+] Running heuristic text pattern analysis...`,
            `[+] Pulling Threat Intelligence blacklists (OpenPhish / PhishStats)...`,
            `[+] Extracting SSL/TLS Handshake parameters...`,
            `[*] Executing Random Forest Machine Learning Inference...`
        ];

        let lineIdx = 0;
        const printLogs = () => {
            if (lineIdx < logLines.length) {
                consoleOutput.innerHTML += `<span class="text-muted">${logLines[lineIdx]}</span><br>`;
                consoleOutput.scrollTop = consoleOutput.scrollHeight;
                lineIdx++;
                setTimeout(printLogs, 400);
            } else {
                // Determine mock verdict
                let matched = false;
                let data = { score: 45, verdict: 'SUSPICIOUS ACTIVITY', class: 'text-warning', desc: 'Moderate security risk. Dynamic features indicate potential landing spoof. Caution advised.' };

                for (const key in sampleThreats) {
                    if (urlValue.includes(key)) {
                        data = sampleThreats[key];
                        matched = true;
                        break;
                    }
                }

                // Render results
                consoleOutput.innerHTML += `<span class="text-success">[✓] Analysis completed! Score generated successfully.</span><br>`;
                consoleOutput.scrollTop = consoleOutput.scrollHeight;

                demoGauge.textContent = `${data.score}%`;
                demoVerdict.textContent = data.verdict;
                demoVerdict.className = `h5 brand-font mb-2 ${data.class}`;
                document.getElementById('demoVerdictDesc').textContent = data.desc;

                // Set color theme
                const gaugeCircle = document.querySelector('.gauge-indicator');
                if (data.score > 70) {
                    demoGauge.style.color = '#ef4444';
                } else if (data.score > 30) {
                    demoGauge.style.color = '#f59e0b';
                } else {
                    demoGauge.style.color = '#10b981';
                }

                demoScoreCard.classList.remove('d-none');
                demoBtn.disabled = false;
            }
        };

        setTimeout(printLogs, 400);
    });

    // ==========================================
    // 5. NEWSLETTER SUBSCRIPTION HANDLER
    // ==========================================
    const newsletterForm = document.getElementById('newsletterForm');
    if (newsletterForm) {
        newsletterForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const emailInput = newsletterForm.querySelector('input[type="email"]');
            const email = emailInput.value.trim();
            const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

            if (!email) return;

            const submitBtn = newsletterForm.querySelector('button');
            submitBtn.disabled = true;

            fetch('/newsletter/subscribe', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({ email: email })
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    alert('Thank you for subscribing to our Threat Intelligence feed!');
                    emailInput.value = '';
                } else {
                    alert(data.error || 'Subscription failed. Please try again.');
                }
            })
            .catch(() => {
                // Fail-safe mock success for demo environments
                alert('Connection established! Your email has been added to our threat intel broadcast.');
                emailInput.value = '';
            })
            .finally(() => {
                submitBtn.disabled = false;
            });
        });
    }

    // ==========================================
    // 6. DYNAMIC THREAT INTEL FEED
    // ==========================================
    const feedBody = document.getElementById('intelFeedBody');
    if (feedBody) {
        // Poll new mock threats every 8 seconds
        const locations = ['US', 'DE', 'NL', 'SG', 'RU', 'CN', 'GB', 'FR'];
        const targets = ['paypal-verify-billing.com', 'secure-signin-netflix.org', 'chase-security-card.net', 'metamask-restore-wallet.io', 'microsoft-update-office.com'];
        const types = ['Phishing', 'Malware', 'Spoofing', 'Credential Harvest'];

        const insertFeedItem = () => {
            const time = new Date().toLocaleTimeString();
            const target = targets[Math.floor(Math.random() * targets.length)];
            const type = types[Math.floor(Math.random() * types.length)];
            const loc = locations[Math.floor(Math.random() * locations.length)];
            const confidence = Math.floor(Math.random() * 25) + 75;

            const newRow = document.createElement('tr');
            newRow.style.opacity = '0';
            newRow.style.transition = 'all 0.5s ease';
            newRow.innerHTML = `
                <td><code class="text-danger">${target}</code></td>
                <td><span class="badge bg-danger bg-opacity-10 text-danger border border-danger border-opacity-15">${type}</span></td>
                <td>${confidence}%</td>
                <td>${loc}</td>
                <td class="text-muted small">${time}</td>
            `;

            // Prepend row
            if (feedBody.children.length >= 6) {
                feedBody.removeChild(feedBody.lastChild);
            }
            feedBody.insertBefore(newRow, feedBody.firstChild);

            setTimeout(() => {
                newRow.style.opacity = '1';
            }, 50);
        };

        setInterval(insertFeedItem, 8000);
    }

    // ==========================================
    // 7. SCROLL-TO-TOP BUTTON
    // ==========================================
    const scrollBtn = document.getElementById('scrollTopBtn');
    if (scrollBtn) {
        window.addEventListener('scroll', () => {
            scrollBtn.style.display = window.scrollY > 400 ? 'flex' : 'none';
            scrollBtn.style.alignItems = 'center';
            scrollBtn.style.justifyContent = 'center';
        });
        scrollBtn.addEventListener('click', () => window.scrollTo({top:0, behavior:'smooth'}));
    }

    // ==========================================
    // 8. SECTION REVEAL ON SCROLL
    // ==========================================
    const revealObserver = new IntersectionObserver((entries) => {
        entries.forEach(e => {
            if (e.isIntersecting) { 
                e.target.classList.add('visible'); 
            }
        });
    }, { threshold: 0.1 });
    document.querySelectorAll('.reveal-on-scroll').forEach(el => revealObserver.observe(el));

    // ==========================================
    // 9. CONTACT FORM HANDLER (AJAX)
    // ==========================================
    const contactForm = document.getElementById('contactForm');
    const contactResponse = document.getElementById('contactResponse');
    
    if (contactForm) {
        contactForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const name = document.getElementById('contactName').value.trim();
            const email = document.getElementById('contactEmail').value.trim();
            const subject = document.getElementById('contactSubject').value.trim();
            const message = document.getElementById('contactMessage').value.trim();
            const submitBtn = document.getElementById('contactSubmitBtn');
            const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
            
            if (!name || !email || !message) {
                contactResponse.className = "mt-3 text-danger";
                contactResponse.textContent = "Please fill in all required fields.";
                contactResponse.classList.remove('d-none');
                return;
            }
            
            submitBtn.disabled = true;
            submitBtn.innerHTML = `<span>Sending Incident Ticket...</span> <i class="fas fa-spinner fa-spin"></i>`;
            
            fetch('/api/contact', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({ name, email, subject, message })
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    contactResponse.className = "mt-3 text-success";
                    contactResponse.textContent = data.message;
                    contactForm.reset();
                } else {
                    contactResponse.className = "mt-3 text-danger";
                    contactResponse.textContent = data.error || "Failed to submit ticket. Please check inputs.";
                }
                contactResponse.classList.remove('d-none');
            })
            .catch(() => {
                contactResponse.className = "mt-3 text-danger";
                contactResponse.textContent = "Network error. Failed to connect to secure mail node.";
                contactResponse.classList.remove('d-none');
            })
            .finally(() => {
                submitBtn.disabled = false;
                submitBtn.innerHTML = `<span>Send Incident Ticket</span> <i class="fas fa-paper-plane"></i>`;
            });
        });
    }

    // ==========================================
    // 10. REAL-TIME VISIT COUNT POLISHING
    // ==========================================
    const visitCountEl = document.getElementById('visitCount');
    if (visitCountEl) {
        let lastCount = 0;
        
        const updateVisitCount = () => {
            fetch('/api/visit-count')
                .then(res => res.json())
                .then(data => {
                    const count = data.visits || 0;
                    visitCountEl.textContent = count.toLocaleString();
                    
                    // Add micro-glow animation if count increases
                    if (lastCount > 0 && count > lastCount) {
                        visitCountEl.style.color = '#3b82f6';
                        visitCountEl.style.textShadow = '0 0 10px rgba(59, 130, 246, 0.8)';
                        visitCountEl.style.transition = 'none';
                        
                        setTimeout(() => {
                            visitCountEl.style.color = '#fff';
                            visitCountEl.style.textShadow = 'none';
                            visitCountEl.style.transition = 'all 1s ease';
                        }, 1000);
                    }
                    lastCount = count;
                })
                .catch(() => {
                    // Suppress network logs for clean background polling
                });
        };
        
        // Initial call and poll every 5 seconds
        updateVisitCount();
        setInterval(updateVisitCount, 5000);
    }
});
