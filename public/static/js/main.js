/**
 * Password Strength Evaluation Based on Modern Attack Techniques
 * JavaScript Controller — 6-Step Proposed System Workflow Execution
 */

document.addEventListener('DOMContentLoaded', () => {
    // ------------------------------------------------------------------
    // DOM Element References
    // ------------------------------------------------------------------
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
    // STEP TRACKER ANIMATION (Steps 1–6)
    // ------------------------------------------------------------------
    function updateWorkflowTracker(stepIndex) {
        for (let i = 1; i <= 6; i++) {
            const stepEl = document.getElementById(`tstep${i}`);
            const badgeEl = document.getElementById(`sbadge${i}`);
            const divEl = document.getElementById(`tdiv${i}`);

            if (!stepEl || !badgeEl) continue;

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
    // LOCAL CLIENT-SIDE GENERATOR (Guaranteed 0ms Instant Response)
    // ------------------------------------------------------------------
    function generatePasswordLocal(length, useUpper, useLower, useDigits, useSymbols) {
        let chars = '';
        if (useUpper) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        if (useLower) chars += 'abcdefghijklmnopqrstuvwxyz';
        if (useDigits) chars += '0123456789';
        if (useSymbols) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';

        if (!chars) chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';

        const guaranteed = [];
        if (useUpper) guaranteed.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ'[Math.floor(Math.random() * 26)]);
        if (useLower) guaranteed.push('abcdefghijklmnopqrstuvwxyz'[Math.floor(Math.random() * 26)]);
        if (useDigits) guaranteed.push('0123456789'[Math.floor(Math.random() * 10)]);
        if (useSymbols) guaranteed.push('!@#$%^&*()_+-=[]{}|;:,.<>?'[Math.floor(Math.random() * 26)]);

        const remaining = Math.max(0, length - guaranteed.length);
        const randomValues = new Uint32Array(remaining);
        if (window.crypto && window.crypto.getRandomValues) {
            window.crypto.getRandomValues(randomValues);
        }
        const randomChars = [];
        for (let i = 0; i < remaining; i++) {
            const randVal = window.crypto ? randomValues[i] : Math.floor(Math.random() * 1e9);
            randomChars.push(chars[randVal % chars.length]);
        }

        const combined = guaranteed.concat(randomChars);
        for (let i = combined.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [combined[i], combined[j]] = [combined[j], combined[i]];
        }
        return combined.join('');
    }

    // ------------------------------------------------------------------
    // REAL-TIME LOCAL EVALUATION (Instant Zero-Lag Feedback)
    // ------------------------------------------------------------------
    function computeLocalMetrics(pwd) {
        const length = pwd.length;
        const upperCount = (pwd.match(/[A-Z]/g) || []).length;
        const lowerCount = (pwd.match(/[a-z]/g) || []).length;
        const digitCount = (pwd.match(/\d/g) || []).length;
        const symbolCount = (pwd.match(/[^a-zA-Z0-9]/g) || []).length;

        let poolSize = 0;
        if (lowerCount > 0) poolSize += 26;
        if (upperCount > 0) poolSize += 26;
        if (digitCount > 0) poolSize += 10;
        if (symbolCount > 0) poolSize += 32;

        const entropy = poolSize > 0 ? Math.round(length * Math.log2(poolSize) * 100) / 100 : 0;

        let baseScore = 0;
        if (length >= 16) baseScore += 25;
        else if (length >= 12) baseScore += 20;
        else if (length >= 10) baseScore += 15;
        else if (length >= 8) baseScore += 10;
        else baseScore += 5;

        if (upperCount > 0) baseScore += 10;
        if (lowerCount > 0) baseScore += 10;
        if (digitCount > 0) baseScore += 10;
        if (symbolCount > 0) baseScore += 15;

        if (entropy >= 60) baseScore += 20;
        else if (entropy >= 35) baseScore += 10;

        const finalScore = Math.min(100, Math.max(0, baseScore));
        let verdict = 'Very Weak';
        let color = '#ef4444';

        if (finalScore > 90) {
            verdict = 'Very Strong';
            color = '#22c55e';
        } else if (finalScore > 70) {
            verdict = 'Strong';
            color = '#00d4ff';
        } else if (finalScore > 50) {
            verdict = 'Medium';
            color = '#f59e0b';
        } else if (finalScore > 30) {
            verdict = 'Weak';
            color = '#f97316';
        }

        return {
            length,
            upperCount,
            lowerCount,
            digitCount,
            symbolCount,
            entropy,
            score: finalScore,
            verdict,
            color
        };
    }

    // ------------------------------------------------------------------
    // REAL-TIME PASSWORD EVALUATION FUNCTION
    // ------------------------------------------------------------------
    function evaluatePasswordRealtime() {
        if (!passwordInput) return;
        const pwd = passwordInput.value;

        if (!pwd) {
            updateWorkflowTracker(1);
            resetUI();
            return;
        }

        // Instant Local Pre-Evaluation (Live UI Synchronized Immediately)
        const local = computeLocalMetrics(pwd);
        updateWorkflowTracker(2);

        if (step1Status) step1Status.textContent = `Password received (${local.length} chars).`;
        if (step2Length) step2Length.textContent = local.length;
        if (step2Upper) step2Upper.textContent = local.upperCount;
        if (step2Lower) step2Lower.textContent = local.lowerCount;
        if (step2Digits) step2Digits.textContent = local.digitCount;
        if (step2Symbols) step2Symbols.textContent = local.symbolCount;

        if (hudScore) {
            hudScore.textContent = `${local.score}/100`;
            hudScore.style.color = local.color;
        }
        if (hudEntropy) hudEntropy.textContent = `${local.entropy} bits`;
        if (hudRisk) {
            hudRisk.textContent = local.verdict;
            hudRisk.style.color = local.color;
        }
        if (progressFill) {
            progressFill.style.width = `${local.score}%`;
            progressFill.style.backgroundColor = local.color;
        }
        if (strengthVal) {
            strengthVal.textContent = local.verdict;
            strengthVal.style.color = local.color;
        }
        if (outScore) {
            outScore.textContent = `${local.score} / 100`;
            outScore.style.color = local.color;
        }
        if (outVerdict) {
            outVerdict.textContent = local.verdict;
            outVerdict.className = local.score > 70 ? 'risk-tag risk-safe' : (local.score > 40 ? 'risk-tag risk-medium' : 'risk-tag risk-high');
        }

        // Backend Deep Threat Evaluation Call
        const endpoints = ['/evaluate', '/api/evaluate', '/'];
        
        function tryFetch(endpointIdx) {
            if (endpointIdx >= endpoints.length) return;
            const endpoint = endpoints[endpointIdx];

            fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: pwd })
            })
            .then(res => {
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                return res.json();
            })
            .then(data => {
                if (data && typeof data.score !== 'undefined') {
                    updateWorkflowTracker(6);
                    updateUI(data);
                }
            })
            .catch(() => {
                // Try next endpoint fallback
                tryFetch(endpointIdx + 1);
            });
        }

        tryFetch(0);
    }

    function updateUI(data) {
        if (!data) return;

        // HUD Metrics
        if (hudScore) {
            hudScore.textContent = `${data.score}/100`;
            hudScore.style.color = data.color;
        }
        if (hudEntropy) hudEntropy.textContent = `${data.entropy} bits`;
        if (hudCrackTime && data.attacker_profiles) {
            hudCrackTime.textContent = data.attacker_profiles.high_gpu_time;
            hudCrackTime.style.color = data.color;
        }
        if (hudRisk) {
            hudRisk.textContent = data.verdict;
            hudRisk.style.color = data.color;
        }

        // Progress Fill
        if (progressFill) {
            progressFill.style.width = `${data.score}%`;
            progressFill.style.backgroundColor = data.color;
        }
        if (strengthVal) {
            strengthVal.textContent = data.verdict;
            strengthVal.style.color = data.color;
        }

        // Step 3 Dictionary Match
        if (step3Result) step3Result.textContent = data.dict_message || 'No dictionary match.';
        if (step3Tag) {
            if (data.dict_match) {
                step3Tag.className = 'risk-tag risk-high';
                step3Tag.textContent = 'DICTIONARY MATCH FOUND';
            } else {
                step3Tag.className = 'risk-tag risk-safe';
                step3Tag.textContent = 'NO DICTIONARY MATCH';
            }
        }

        // Step 4 Pattern Analysis
        if (step4Pattern) step4Pattern.textContent = data.pattern_summary || 'No predictable structural patterns detected.';
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
        if (data.attacker_profiles) {
            if (cpuTime) cpuTime.textContent = data.attacker_profiles.cpu_time;
            if (gpuTime) gpuTime.textContent = data.attacker_profiles.gpu_time;
            if (highGpuTime) highGpuTime.textContent = data.attacker_profiles.high_gpu_time;

            // Update Chart
            if (crackChart) {
                try {
                    const cpuSec = Math.max(1, Math.min(100, Math.log10((data.attacker_profiles.cpu_seconds || 0) + 1) * 20));
                    const gpuSec = Math.max(1, Math.min(100, Math.log10((data.attacker_profiles.gpu_seconds || 0) + 1) * 20));
                    const hgSec = Math.max(1, Math.min(100, Math.log10((data.attacker_profiles.high_gpu_seconds || 0) + 1) * 20));

                    crackChart.data.datasets[0].data = [cpuSec, gpuSec, hgSec];
                    crackChart.update();
                } catch (e) {
                    console.warn('Chart update notice:', e);
                }
            }
        }

        // Step 6 Output Box
        if (outScore) {
            outScore.textContent = `${data.score} / 100`;
            outScore.style.color = data.color;
        }
        if (outVerdict) {
            outVerdict.textContent = data.verdict;
            outVerdict.className = data.score > 70 ? 'risk-tag risk-safe' : (data.score > 40 ? 'risk-tag risk-medium' : 'risk-tag risk-high');
        }
        if (outPattern) outPattern.textContent = data.pattern_summary || 'None';
        if (outCrackTime && data.attacker_profiles) {
            outCrackTime.textContent = data.attacker_profiles.high_gpu_time;
        }
        if (outSuggestion) outSuggestion.textContent = data.suggestion || 'Strong password.';

        // Update Report URL link
        if (reportBtn && passwordInput) {
            reportBtn.href = `/result?pwd=${encodeURIComponent(passwordInput.value)}`;
        }
    }

    function resetUI() {
        if (hudScore) hudScore.textContent = '0/100';
        if (hudEntropy) hudEntropy.textContent = '0 bits';
        if (hudCrackTime) hudCrackTime.textContent = 'Instant';
        if (hudRisk) hudRisk.textContent = 'Very Weak';

        if (progressFill) progressFill.style.width = '0%';
        if (strengthVal) strengthVal.textContent = 'Very Weak';

        if (step1Status) step1Status.textContent = 'Awaiting password input...';
        if (step2Length) step2Length.textContent = '0';
        if (step2Upper) step2Upper.textContent = '0';
        if (step2Lower) step2Lower.textContent = '0';
        if (step2Digits) step2Digits.textContent = '0';
        if (step2Symbols) step2Symbols.textContent = '0';

        if (step3Result) step3Result.textContent = 'No input password provided.';
        if (step3Tag) {
            step3Tag.className = 'risk-tag risk-safe';
            step3Tag.textContent = 'NO DICTIONARY MATCH';
        }

        if (step4Pattern) step4Pattern.textContent = 'No predictable structural patterns detected.';
        if (step4Badges) step4Badges.innerHTML = '';

        if (cpuTime) cpuTime.textContent = 'Instant';
        if (gpuTime) gpuTime.textContent = 'Instant';
        if (highGpuTime) highGpuTime.textContent = 'Instant';

        if (outScore) outScore.textContent = '0 / 100';
        if (outVerdict) outVerdict.textContent = 'Very Weak';
        if (outPattern) outPattern.textContent = 'None';
        if (outCrackTime) outCrackTime.textContent = 'Instant';
        if (outSuggestion) outSuggestion.textContent = 'Enter a strong, unpredictable passphrase.';
    }

    // ------------------------------------------------------------------
    // EVENT LISTENERS (Attached Immediately for Guaranteed Responsiveness)
    // ------------------------------------------------------------------
    if (passwordInput) {
        passwordInput.addEventListener('input', evaluatePasswordRealtime);
        passwordInput.addEventListener('keyup', evaluatePasswordRealtime);
        passwordInput.addEventListener('change', evaluatePasswordRealtime);
    }

    if (evaluateBtn) {
        evaluateBtn.addEventListener('click', (e) => {
            e.preventDefault();
            evaluatePasswordRealtime();
        });
    }

    if (togglePwdBtn && passwordInput) {
        togglePwdBtn.addEventListener('click', (e) => {
            e.preventDefault();
            const isPwd = passwordInput.type === 'password';
            passwordInput.type = isPwd ? 'text' : 'password';
            togglePwdBtn.innerHTML = isPwd ? '<i class="fas fa-eye-slash"></i>' : '<i class="fas fa-eye"></i>';
        });
    }

    if (copyPwdBtn && passwordInput) {
        copyPwdBtn.addEventListener('click', (e) => {
            e.preventDefault();
            const val = passwordInput.value;
            if (!val) return;

            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(val).then(() => {
                    const orig = copyPwdBtn.innerHTML;
                    copyPwdBtn.innerHTML = '<i class="fas fa-check"></i> Copied!';
                    setTimeout(() => { copyPwdBtn.innerHTML = orig; }, 2000);
                }).catch(() => {
                    fallbackCopy(val);
                });
            } else {
                fallbackCopy(val);
            }
        });

        function fallbackCopy(text) {
            passwordInput.select();
            document.execCommand('copy');
            const orig = copyPwdBtn.innerHTML;
            copyPwdBtn.innerHTML = '<i class="fas fa-check"></i> Copied!';
            setTimeout(() => { copyPwdBtn.innerHTML = orig; }, 2000);
        }
    }

    // Generator Controls
    if (genLengthSlider && genLengthVal) {
        genLengthSlider.addEventListener('input', () => {
            genLengthVal.textContent = genLengthSlider.value;
        });
    }

    if (genActionBtn && passwordInput) {
        genActionBtn.addEventListener('click', (e) => {
            e.preventDefault();

            const len = parseInt(genLengthSlider ? genLengthSlider.value : 16);
            const u = genUpper ? genUpper.checked : true;
            const l = genLower ? genLower.checked : true;
            const n = genNumbers ? genNumbers.checked : true;
            const s = genSymbols ? genSymbols.checked : true;

            // 1. Instant local cryptographic generation (0ms latency guaranteed)
            const localPw = generatePasswordLocal(len, u, l, n, s);
            passwordInput.value = localPw;
            passwordInput.type = 'text';
            if (togglePwdBtn) togglePwdBtn.innerHTML = '<i class="fas fa-eye-slash"></i>';

            // Trigger real-time evaluation immediately
            evaluatePasswordRealtime();

            // 2. Background sync with backend generator API
            const params = new URLSearchParams({
                length: len,
                uppercase: u,
                lowercase: l,
                numbers: n,
                symbols: s
            });

            fetch(`/generate?${params.toString()}`)
                .then(res => res.ok ? res.json() : null)
                .then(data => {
                    if (data && data.password) {
                        passwordInput.value = data.password;
                        evaluatePasswordRealtime();
                    }
                })
                .catch(() => {
                    // Local generator already populated passwordInput seamlessly
                });
        });
    }

    // ------------------------------------------------------------------
    // SAFE CHART INITIALIZATION (Guarded Against Missing CDN)
    // ------------------------------------------------------------------
    try {
        const chartCanvas = document.getElementById('crackTimeChart');
        if (chartCanvas && typeof Chart !== 'undefined') {
            const ctx = chartCanvas.getContext('2d');
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
    } catch (err) {
        console.warn('Chart initialization safely bypassed:', err);
    }
});
