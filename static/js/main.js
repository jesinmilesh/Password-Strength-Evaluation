/* ==========================================================================
   CYBER SHIELD - REAL-TIME JAVASCRIPT ENGINE & BUTTON EVENT HANDLERS
   ========================================================================== */

document.addEventListener('DOMContentLoaded', () => {
    // DOM Element Declarations
    const passwordInput = document.getElementById('passwordInput');
    const togglePwdBtn = document.getElementById('togglePwdBtn');
    const copyPwdBtn = document.getElementById('copyPwdBtn');
    const evaluateBtn = document.getElementById('evaluateBtn');
    const reportBtn = document.getElementById('reportBtn');

    // Strength Meter & Header
    const strengthVal = document.getElementById('strengthVal');
    const progressFill = document.getElementById('progressFill');

    // Dashboard HUD Cards
    const hudScore = document.getElementById('hudScore');
    const hudEntropy = document.getElementById('hudEntropy');
    const hudCrackTime = document.getElementById('hudCrackTime');
    const hudRisk = document.getElementById('hudRisk');

    // Workflow Pipeline Elements
    const step1Status = document.getElementById('step1Status');
    const step2Length = document.getElementById('step2Length');
    const step2Categories = document.getElementById('step2Categories');
    const step3Result = document.getElementById('step3Result');
    const step3Tag = document.getElementById('step3Tag');
    const step4Pattern = document.getElementById('step4Pattern');

    // Hardware Profiles Table
    const cpuTime = document.getElementById('cpuTime');
    const gpuTime = document.getElementById('gpuTime');
    const highGpuTime = document.getElementById('highGpuTime');

    // Step 6 Output Result Table
    const outScore = document.getElementById('outScore');
    const outVerdict = document.getElementById('outVerdict');
    const outPattern = document.getElementById('outPattern');
    const outCrackTime = document.getElementById('outCrackTime');
    const outSuggestion = document.getElementById('outSuggestion');

    // Password Generator Controls
    const genLengthSlider = document.getElementById('genLengthSlider');
    const genLengthVal = document.getElementById('genLengthVal');
    const genUpper = document.getElementById('genUpper');
    const genLower = document.getElementById('genLower');
    const genNumbers = document.getElementById('genNumbers');
    const genSymbols = document.getElementById('genSymbols');
    const genActionBtn = document.getElementById('genActionBtn');

    // Chart.js instance
    let crackChart = null;

    // ----------------------------------------------------------------------
    // INITIALIZATION
    // ----------------------------------------------------------------------
    initCrackTimeChart([0.1, 0.1, 0.1]);

    if (passwordInput && passwordInput.value) {
        handleEvaluatePassword(passwordInput.value);
    }

    // ----------------------------------------------------------------------
    // DEDICATED BUTTON HANDLERS & EVENT LISTENERS
    // ----------------------------------------------------------------------

    // 1. Real-time Typing Handler (0ms Latency Evaluation)
    if (passwordInput) {
        passwordInput.addEventListener('input', (e) => {
            handleEvaluatePassword(e.target.value);
            updateReportLink(e.target.value);
        });
    }

    // 2. Evaluate Password Button Handler
    if (evaluateBtn && passwordInput) {
        evaluateBtn.addEventListener('click', () => {
            handleEvaluatePassword(passwordInput.value);
            showToast("Password threat evaluation executed!");
        });
    }

    // 3. Toggle Password Visibility Handler
    if (togglePwdBtn && passwordInput) {
        togglePwdBtn.addEventListener('click', () => {
            handleTogglePassword();
        });
    }

    function handleTogglePassword() {
        const isPassword = passwordInput.type === 'password';
        passwordInput.type = isPassword ? 'text' : 'password';
        togglePwdBtn.innerHTML = isPassword ? '<i class="fas fa-eye-slash"></i>' : '<i class="fas fa-eye"></i>';
        showToast(isPassword ? "Password visible" : "Password hidden");
    }

    // 4. Copy Password Button Handler
    if (copyPwdBtn && passwordInput) {
        copyPwdBtn.addEventListener('click', () => {
            handleCopyPassword();
        });
    }

    function handleCopyPassword() {
        if (!passwordInput.value) {
            showToast('Password field is empty!');
            return;
        }
        navigator.clipboard.writeText(passwordInput.value).then(() => {
            showToast('Password copied to clipboard!');
        }).catch(() => {
            showToast('Failed to copy password.');
        });
    }

    // 5. Generator Length Slider Handler
    if (genLengthSlider && genLengthVal) {
        genLengthSlider.addEventListener('input', (e) => {
            genLengthVal.textContent = e.target.value;
        });
    }

    // 6. Generate Password Button Handler
    if (genActionBtn) {
        genActionBtn.addEventListener('click', () => {
            handleGeneratePassword();
        });
    }

    function handleGeneratePassword() {
        const length = genLengthSlider ? genLengthSlider.value : 16;
        const uppercase = genUpper ? genUpper.checked : true;
        const lowercase = genLower ? genLower.checked : true;
        const numbers = genNumbers ? genNumbers.checked : true;
        const symbols = genSymbols ? genSymbols.checked : true;

        fetch(`/generate?length=${length}&uppercase=${uppercase}&lowercase=${lowercase}&numbers=${numbers}&symbols=${symbols}`)
            .then(res => res.json())
            .then(data => {
                if (passwordInput) {
                    passwordInput.value = data.password;
                    passwordInput.type = 'text';
                    if (togglePwdBtn) togglePwdBtn.innerHTML = '<i class="fas fa-eye-slash"></i>';
                    updateUI(data.evaluation);
                    updateReportLink(data.password);
                    showToast('Generated secure random password!');
                }
            })
            .catch(err => console.error("Generation error:", err));
    }

    // 7. Update Report Link URL
    function updateReportLink(pwd) {
        if (reportBtn) {
            reportBtn.href = `/result?pwd=${encodeURIComponent(pwd)}`;
        }
    }

    // ----------------------------------------------------------------------
    // CORE EVALUATION & UI UPDATE LOGIC
    // ----------------------------------------------------------------------
    function handleEvaluatePassword(pwd) {
        fetch('/evaluate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: pwd })
        })
        .then(res => res.json())
        .then(data => {
            updateUI(data);
        })
        .catch(err => console.error("Evaluation error:", err));
    }

    function updateUI(data) {
        // 1. Progress Bar & Verdict Header
        if (strengthVal) {
            strengthVal.textContent = data.verdict;
            strengthVal.style.color = data.color;
        }

        if (progressFill) {
            progressFill.style.width = `${data.score}%`;
            progressFill.style.backgroundColor = data.color;
            progressFill.style.boxShadow = `0 0 15px ${data.color}`;
        }

        // 2. HUD Cards
        if (hudScore) {
            hudScore.textContent = `${data.score}/100`;
            hudScore.style.color = data.color;
        }
        if (hudEntropy) hudEntropy.textContent = `${data.entropy} bits`;
        if (hudCrackTime) hudCrackTime.textContent = data.attacker_profiles.high_gpu_time;
        if (hudRisk) {
            hudRisk.textContent = data.verdict;
            hudRisk.style.color = data.color;
        }

        // 3. Step 1 & 2 Workflow
        if (step1Status) step1Status.textContent = data.password_received || "Awaiting password input...";
        if (step2Length) step2Length.textContent = `${data.preprocessing.length} Characters`;
        if (step2Categories) step2Categories.textContent = data.preprocessing.category_summary;

        // 4. Step 3 Dictionary Match
        if (step3Result) {
            step3Result.textContent = data.dict_message;
        }
        if (step3Tag) {
            if (data.dict_match) {
                step3Tag.textContent = "THREAT DATASET MATCH DETECTED";
                step3Tag.className = "risk-tag risk-high";
            } else {
                step3Tag.textContent = "NO BREACH MATCH";
                step3Tag.className = "risk-tag risk-safe";
            }
        }

        // 5. Step 4 Pattern Analysis
        if (step4Pattern) {
            step4Pattern.textContent = data.pattern_summary;
        }

        // 6. Step 5 Hardware Profiles Table
        if (cpuTime) cpuTime.textContent = data.attacker_profiles.cpu_time;
        if (gpuTime) gpuTime.textContent = data.attacker_profiles.gpu_time;
        if (highGpuTime) highGpuTime.textContent = data.attacker_profiles.high_gpu_time;

        // Update Chart.js graph
        updateCrackTimeChart([
            data.attacker_profiles.cpu_seconds,
            data.attacker_profiles.gpu_seconds,
            data.attacker_profiles.high_gpu_seconds
        ]);

        // 7. Step 6 Verdict Output Table
        if (outScore) {
            outScore.textContent = `${data.score} / 100`;
            outScore.style.color = data.color;
        }
        if (outVerdict) {
            outVerdict.textContent = data.verdict;
            outVerdict.style.backgroundColor = `${data.color}22`;
            outVerdict.style.borderColor = data.color;
            outVerdict.style.color = data.color;
        }
        if (outPattern) outPattern.textContent = data.pattern_summary;
        if (outCrackTime) outCrackTime.textContent = data.attacker_profiles.summary_display;
        if (outSuggestion) outSuggestion.textContent = data.suggestion;
    }

    // Chart.js Initialization
    function initCrackTimeChart(initialData) {
        const ctx = document.getElementById('crackTimeChart');
        if (!ctx) return;

        crackChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['Single CPU', 'Consumer GPU', 'High-End GPU'],
                datasets: [{
                    label: 'Est. Crack Time (Seconds)',
                    data: initialData,
                    backgroundColor: [
                        'rgba(0, 240, 255, 0.6)',
                        'rgba(255, 153, 0, 0.6)',
                        'rgba(255, 51, 102, 0.6)'
                    ],
                    borderColor: [
                        '#00f0ff',
                        '#ff9900',
                        '#ff3366'
                    ],
                    borderWidth: 1.5,
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        type: 'logarithmic',
                        ticks: { color: '#94a3b8' },
                        grid: { color: 'rgba(255, 255, 255, 0.05)' }
                    },
                    x: {
                        ticks: { color: '#f1f5f9' },
                        grid: { display: false }
                    }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }

    function updateCrackTimeChart(newData) {
        if (!crackChart) return;
        const cleanData = newData.map(val => Math.max(0.1, val));
        crackChart.data.datasets[0].data = cleanData;
        crackChart.update();
    }

    // Toast Notifications
    function showToast(message) {
        let toastContainer = document.querySelector('.toast-container');
        if (!toastContainer) {
            toastContainer = document.createElement('div');
            toastContainer.className = 'toast-container';
            document.body.appendChild(toastContainer);
        }

        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.innerHTML = `<i class="fas fa-info-circle" style="color: var(--neon-blue);"></i> <span>${message}</span>`;
        toastContainer.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(20px)';
            toast.style.transition = 'all 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }
});
