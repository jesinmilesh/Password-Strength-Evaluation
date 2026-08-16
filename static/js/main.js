/**
 * Password Strength Evaluation Based on Modern Attack Techniques
 * JavaScript Controller — 6-Step Proposed System Workflow Execution
 */

document.addEventListener('DOMContentLoaded', () => {
    // DOM Element References
    const passwordInput = document.getElementById('passwordInput');
    const togglePwdBtn = document.getElementById('togglePwdBtn');
    const evaluateBtn = document.getElementById('evaluateBtn');
    const copyPwdBtn = document.getElementById('copyPwdBtn');
    const reportBtn = document.getElementById('reportBtn');
    const progressFill = document.getElementById('progressFill');
    const strengthVal = document.getElementById('strengthVal');

    // HUD Summary Cards
    const hudScore = document.getElementById('hudScore');
    const hudEntropy = document.getElementById('hudEntropy');
    const hudCrackTime = document.getElementById('hudCrackTime');
    const hudRisk = document.getElementById('hudRisk');

    // Step Display Elements
    const step1Status = document.getElementById('step1Status');
    const step2Length = document.getElementById('step2Length');
    const step2Upper = document.getElementById('step2Upper');
    const step2Lower = document.getElementById('step2Lower');
    const step2Digits = document.getElementById('step2Digits');
    const step2Symbols = document.getElementById('step2Symbols');

    const step3Result = document.getElementById('step3Result');
    const step3Tag = document.getElementById('step3Tag');
    const step4Pattern = document.getElementById('step4Pattern');
    const step4Badges = document.getElementById('step4Badges');

    const cpuTime = document.getElementById('cpuTime');
    const gpuTime = document.getElementById('gpuTime');
    const highGpuTime = document.getElementById('highGpuTime');

    const outScore = document.getElementById('outScore');
    const outVerdict = document.getElementById('outVerdict');
    const outPattern = document.getElementById('outPattern');
    const outCrackTime = document.getElementById('outCrackTime');
    const outSuggestion = document.getElementById('outSuggestion');

    // Generator Elements
    const genActionBtn = document.getElementById('genActionBtn');
    const genLengthSlider = document.getElementById('genLengthSlider');
    const genLengthVal = document.getElementById('genLengthVal');
    const genUpper = document.getElementById('genUpper');
    const genLower = document.getElementById('genLower');
    const genNumbers = document.getElementById('genNumbers');
    const genSymbols = document.getElementById('genSymbols');

    let crackChart = null;

    // ------------------------------------------------------------------
    // CHART.JS INITIALIZATION (Step 5 Crack Time Graph)
    // ------------------------------------------------------------------
    function initChart() {
        const ctx = document.getElementById('crackTimeChart').getContext('2d');
        crackChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['Single CPU', 'Consumer GPU', 'High-End Cluster'],
                datasets: [{
                    label: 'Estimated Crack Time (log scale)',
                    data: [1, 1, 1],
                    backgroundColor: [
                        'rgba(0, 240, 255, 0.7)',
                        'rgba(255, 204, 0, 0.7)',
                        'rgba(255, 51, 102, 0.7)'
                    ],
                    borderColor: [
                        '#00f0ff',
                        '#ffcc00',
                        '#ff3366'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#94a3b8' }
                    },
                    x: {
                        grid: { display: false },
                        ticks: { color: '#94a3b8' }
                    }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }

    if (document.getElementById('crackTimeChart')) {
        initChart();
    }

    // ------------------------------------------------------------------
    // STEP TRACKER ANIMATION (Steps 1–6)
    // ------------------------------------------------------------------
    function updateWorkflowTracker(stepIndex) {
        for (let i = 1; i <= 6; i++) {
            const stepEl = document.getElementById(`tstep${i}`);
            const badgeEl = document.getElementById(`sbadge${i}`);
            const divEl = document.getElementById(`tdiv${i}`);

            if (i < stepIndex) {
                stepEl.className = 'tracker-step completed';
                badgeEl.innerHTML = '<i class="fas fa-check"></i>';
                if (divEl) divEl.className = 'tracker-divider active';
            } else if (i === stepIndex) {
                stepEl.className = 'tracker-step active';
                badgeEl.textContent = i;
                if (divEl) divEl.className = 'tracker-divider';
            } else {
                stepEl.className = 'tracker-step';
                badgeEl.textContent = i;
                if (divEl) divEl.className = 'tracker-divider';
            }
        }
    }

    // ------------------------------------------------------------------
    // REAL-TIME PASSWORD EVALUATION FUNCTION
    // ------------------------------------------------------------------
    function evaluatePasswordRealtime() {
        const pwd = passwordInput.value;

        if (!pwd) {
            updateWorkflowTracker(1);
            resetUI();
            return;
        }

        // Trigger Step 1 & 2 locally before API response
        updateWorkflowTracker(2);
        step1Status.textContent = `Password received (${pwd.length} chars).`;
        step2Length.textContent = pwd.length;
        step2Upper.textContent = (pwd.match(/[A-Z]/g) || []).length;
        step2Lower.textContent = (pwd.match(/[a-z]/g) || []).length;
        step2Digits.textContent = (pwd.match(/\d/g) || []).length;
        step2Symbols.textContent = (pwd.match(/[^a-zA-Z0-9]/g) || []).length;

        fetch('/evaluate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: pwd })
        })
        .then(res => res.json())
        .then(data => {
            // Animate workflow steps to step 6
            updateWorkflowTracker(6);
            updateUI(data);
        })
        .catch(err => {
            console.error('Evaluation API error:', err);
        });
    }

    function updateUI(data) {
        // HUD Metrics
        hudScore.textContent = `${data.score}/100`;
        hudScore.style.color = data.color;

        hudEntropy.textContent = `${data.entropy} bits`;
        hudCrackTime.textContent = data.attacker_profiles.high_gpu_time;
        hudCrackTime.style.color = data.color;

        hudRisk.textContent = data.verdict;
        hudRisk.style.color = data.color;

        // Progress Fill
        progressFill.style.width = `${data.score}%`;
        progressFill.style.backgroundColor = data.color;
        strengthVal.textContent = data.verdict;
        strengthVal.style.color = data.color;

        // Step 3 Dictionary Match
        step3Result.textContent = data.dict_message;
        if (data.dict_match) {
            step3Tag.className = 'risk-tag risk-high';
            step3Tag.textContent = 'DICTIONARY MATCH FOUND';
        } else {
            step3Tag.className = 'risk-tag risk-safe';
            step3Tag.textContent = 'NO DICTIONARY MATCH';
        }

        // Step 4 Pattern Analysis
        step4Pattern.textContent = data.pattern_summary;
        if (step4Badges) {
            step4Badges.innerHTML = '';
            if (data.step4 && data.step4.risks && data.step4.risks.length > 0) {
                data.step4.risks.forEach(r => {
                    const b = document.createElement('span');
                    b.className = 'risk-tag risk-high';
                    b.style.fontSize = '11px';
                    b.textContent = r.type;
                    step4Badges.appendChild(b);
                });
            }
        }

        // Step 5 Hardware Profiles
        cpuTime.textContent = data.attacker_profiles.cpu_time;
        gpuTime.textContent = data.attacker_profiles.gpu_time;
        highGpuTime.textContent = data.attacker_profiles.high_gpu_time;

        // Update Chart
        if (crackChart) {
            const cpuSec = Math.max(1, Math.min(100, Math.log10(data.attacker_profiles.cpu_seconds + 1) * 20));
            const gpuSec = Math.max(1, Math.min(100, Math.log10(data.attacker_profiles.gpu_seconds + 1) * 20));
            const hgSec = Math.max(1, Math.min(100, Math.log10(data.attacker_profiles.high_gpu_seconds + 1) * 20));

            crackChart.data.datasets[0].data = [cpuSec, gpuSec, hgSec];
            crackChart.update();
        }

        // Step 6 Output Box
        outScore.textContent = `${data.score} / 100`;
        outScore.style.color = data.color;

        outVerdict.textContent = data.verdict;
        outVerdict.className = data.score > 70 ? 'risk-tag risk-safe' : (data.score > 40 ? 'risk-tag risk-medium' : 'risk-tag risk-high');

        outPattern.textContent = data.pattern_summary;
        outCrackTime.textContent = data.attacker_profiles.high_gpu_time;
        outSuggestion.textContent = data.suggestion;

        // Update Report URL link
        if (reportBtn) {
            reportBtn.href = `/result?pwd=${encodeURIComponent(passwordInput.value)}`;
        }
    }

    function resetUI() {
        hudScore.textContent = '0/100';
        hudEntropy.textContent = '0 bits';
        hudCrackTime.textContent = 'Instant';
        hudRisk.textContent = 'Very Weak';

        progressFill.style.width = '0%';
        strengthVal.textContent = 'Very Weak';

        step1Status.textContent = 'Awaiting password input...';
        step2Length.textContent = '0';
        step2Upper.textContent = '0';
        step2Lower.textContent = '0';
        step2Digits.textContent = '0';
        step2Symbols.textContent = '0';

        step3Result.textContent = 'No input password provided.';
        step3Tag.className = 'risk-tag risk-safe';
        step3Tag.textContent = 'NO DICTIONARY MATCH';

        step4Pattern.textContent = 'No predictable structural patterns detected.';
        if (step4Badges) step4Badges.innerHTML = '';

        cpuTime.textContent = 'Instant';
        gpuTime.textContent = 'Instant';
        highGpuTime.textContent = 'Instant';

        outScore.textContent = '0 / 100';
        outVerdict.textContent = 'Very Weak';
        outPattern.textContent = 'None';
        outCrackTime.textContent = 'Instant';
        outSuggestion.textContent = 'Enter a strong, unpredictable passphrase.';
    }

    // ------------------------------------------------------------------
    // EVENT LISTENERS
    // ------------------------------------------------------------------
    if (passwordInput) {
        passwordInput.addEventListener('input', evaluatePasswordRealtime);
    }

    if (evaluateBtn) {
        evaluateBtn.addEventListener('click', evaluatePasswordRealtime);
    }

    if (togglePwdBtn) {
        togglePwdBtn.addEventListener('click', () => {
            const isPwd = passwordInput.type === 'password';
            passwordInput.type = isPwd ? 'text' : 'password';
            togglePwdBtn.innerHTML = isPwd ? '<i class="fas fa-eye-slash"></i>' : '<i class="fas fa-eye"></i>';
        });
    }

    if (copyPwdBtn) {
        copyPwdBtn.addEventListener('click', () => {
            if (!passwordInput.value) return;
            navigator.clipboard.writeText(passwordInput.value).then(() => {
                const orig = copyPwdBtn.innerHTML;
                copyPwdBtn.innerHTML = '<i class="fas fa-check"></i> Copied!';
                setTimeout(() => { copyPwdBtn.innerHTML = orig; }, 2000);
            });
        });
    }

    // Generator Actions
    if (genLengthSlider) {
        genLengthSlider.addEventListener('input', () => {
            genLengthVal.textContent = genLengthSlider.value;
        });
    }

    if (genActionBtn) {
        genActionBtn.addEventListener('click', () => {
            const params = new URLSearchParams({
                length: genLengthSlider.value,
                uppercase: genUpper.checked,
                lowercase: genLower.checked,
                numbers: genNumbers.checked,
                symbols: genSymbols.checked
            });

            fetch(`/generate?${params.toString()}`)
            .then(res => res.json())
            .then(data => {
                passwordInput.value = data.password;
                passwordInput.type = 'text';
                if (togglePwdBtn) togglePwdBtn.innerHTML = '<i class="fas fa-eye-slash"></i>';
                evaluatePasswordRealtime();
            });
        });
    }
});
