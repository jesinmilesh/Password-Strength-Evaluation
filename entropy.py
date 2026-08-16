import re
import math
import zxcvbn

def calculate_shannon_entropy(password):
    """
    Step 5 – Shannon Entropy Calculation
    Formula: H = len(password) * log2(pool_size)
    """
    if not password:
        return 0.0

    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digits = bool(re.search(r'\d', password))
    has_symbols = bool(re.search(r'[^a-zA-Z0-9]', password))

    pool_size = 0
    if has_lower: pool_size += 26
    if has_upper: pool_size += 26
    if has_digits: pool_size += 10
    if has_symbols: pool_size += 32

    if pool_size == 0:
        return 0.0

    raw_entropy = len(password) * math.log2(pool_size)
    return round(raw_entropy, 2)

def estimate_crack_times(password, is_dictionary_match=False, has_patterns=False):
    """
    Step 5 – Multi-Hardware Attacker Profiles & Crack-Time Estimates
    Profiles: CPU (10k h/s), Consumer GPU (1M h/s), High-End GPU (100B h/s)
    """
    if not password:
        return {
            "cpu_time": "Instant",
            "gpu_time": "Instant",
            "high_gpu_time": "Instant",
            "cpu_seconds": 0,
            "gpu_seconds": 0,
            "high_gpu_seconds": 0,
            "summary_display": "Under 1 second"
        }

    res = zxcvbn.zxcvbn(password)
    guesses = res.get('guesses', 10**6)

    # Penalize guesses if dictionary or pattern match detected
    if is_dictionary_match:
        guesses = min(guesses, 100)
    elif has_patterns:
        guesses = min(guesses, 10000)

    cpu_sec = guesses / 10000.0          # 10k hash/sec
    gpu_sec = guesses / 1000000.0        # 1M hash/sec
    high_gpu_sec = guesses / 1e11       # 100B hash/sec

    def format_time(seconds):
        if seconds < 1: return "Under 10 Seconds" if seconds > 0.1 else "Instant"
        elif seconds < 60: return f"{int(seconds)} seconds"
        elif seconds < 3600: return f"{int(seconds/60)} minutes"
        elif seconds < 86400: return f"{int(seconds/3600)} hours"
        elif seconds < 31536000: return f"{int(seconds/86400)} days"
        elif seconds < 3153600000: return f"{int(seconds/31536000)} years"
        else: return f"{int(seconds/3153600000)} centuries"

    return {
        "cpu_time": format_time(cpu_sec),
        "gpu_time": format_time(gpu_sec),
        "high_gpu_time": format_time(high_gpu_sec),
        "cpu_seconds": round(cpu_sec, 2),
        "gpu_seconds": round(gpu_sec, 2),
        "high_gpu_seconds": round(high_gpu_sec, 2),
        "summary_display": format_time(high_gpu_sec)
    }
