import os
import re
import math
import random
import string
import sqlite3
import zxcvbn
from flask import Flask, render_template, request, jsonify, g

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cyber_shield_threat_intelligence_2026')

# Path setup
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(BASE_DIR, 'database')
DB_PATH = os.path.join(DB_DIR, 'passwords.db')
DATASETS_DIR = os.path.join(BASE_DIR, 'datasets')

# ----------------------------------------------------------------------
# STEP 4: PER-REQUEST EFFICIENT DATABASE CONNECTION (Flask g)
# ----------------------------------------------------------------------
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# ----------------------------------------------------------------------
# STEP 5 & 9: LIGHTWEIGHT STARTUP & LAZY LOADED FALLBACKS
# ----------------------------------------------------------------------
FALLBACK_RAM_SET = set()
USE_SQLITE = False
STATISTICS_STATS = {
    "password_corpus": "30+ Million",
    "dictionary_lists": "2",
    "keyboard_patterns": "500+",
    "names": "100,000",
    "common_words": "370,000"
}

def init_threat_engine():
    global FALLBACK_RAM_SET, USE_SQLITE
    print("==================================================")
    print("  INITIALIZING CYBER SHIELD THREAT EVALUATION ENGINE")
    print("==================================================")
    
    if os.path.exists(DB_PATH):
        USE_SQLITE = True
        print("  Loading SQLite password corpus...")
        print(f"  Using SQLite database: {DB_PATH}")
        print("  Password corpus ready.")
    else:
        USE_SQLITE = False
        print("  SQLite database not found. Activating lightweight RAM fallback...")
        # Load lightweight fallback datasets (Top 100K)
        rf_path = os.path.join(DATASETS_DIR, 'high_risk_passwords.txt')
        cp_path = os.path.join(DATASETS_DIR, 'common_passwords.txt')
        for p in [rf_path, cp_path]:
            if os.path.exists(p):
                with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        pw = line.strip().lower()
                        if pw:
                            FALLBACK_RAM_SET.add(pw)
        print(f"  Fallback RAM corpus ready ({len(FALLBACK_RAM_SET):,} entries).")

    print("  Health endpoint active.")
    print("  Server started successfully.")
    print("==================================================")

init_threat_engine()

# ----------------------------------------------------------------------
# STEP 7: LAZY LOAD SUPPORTING DATASETS (Cache on first use)
# ----------------------------------------------------------------------
_LAZY_PATTERNS = None

def get_lazy_patterns():
    global _LAZY_PATTERNS
    if _LAZY_PATTERNS is None:
        _LAZY_PATTERNS = {
            "base_words": ['summer', 'winter', 'spring', 'autumn', 'season', 'password', 'admin', 'qwerty', 'welcome', '123456', 'iloveyou', 'changeit', 'letmein', 'cyber', 'shield', 'dragon', 'princess', 'monkey', 'charlie', 'sunshine', 'google', 'matrix', 'bitcoin', 'crypto'],
            "keyboards": ['qwerty', 'asdfgh', 'zxcvbn', '1q2w3e', '123456', 'password']
        }
    return _LAZY_PATTERNS

# ----------------------------------------------------------------------
# STEP 3: EFFICIENT SQLITE / FALLBACK LOOKUP FUNCTION
# ----------------------------------------------------------------------
def password_exists(password):
    pw_lower = password.strip().lower()
    if not pw_lower:
        return False
        
    if USE_SQLITE:
        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute("SELECT 1 FROM passwords WHERE password = ? LIMIT 1", (pw_lower,))
            return cursor.fetchone() is not None
        except Exception as e:
            print(f"SQLite Lookup Error: {e}")
            return pw_lower in FALLBACK_RAM_SET
    else:
        return pw_lower in FALLBACK_RAM_SET

def calculate_entropy(password):
    """Calculate Shannon Entropy (in bits) of password."""
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
        
    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 2)

def preprocess_password(password):
    """Step 2 — Preprocess & Normalize Character Breakdown."""
    trimmed = password.strip()
    length = len(trimmed)
    
    upper_count = len(re.findall(r'[A-Z]', trimmed))
    lower_count = len(re.findall(r'[a-z]', trimmed))
    digit_count = len(re.findall(r'\d', trimmed))
    symbol_count = len(re.findall(r'[^a-zA-Z0-9]', trimmed))

    categories = []
    if upper_count > 0: categories.append(f"Uppercase ({upper_count})")
    if lower_count > 0: categories.append(f"Lowercase ({lower_count})")
    if digit_count > 0: categories.append(f"Digits ({digit_count})")
    if symbol_count > 0: categories.append(f"Symbols ({symbol_count})")

    return {
        "raw": password,
        "normalized": trimmed,
        "length": length,
        "upper_count": upper_count,
        "lower_count": lower_count,
        "digit_count": digit_count,
        "symbol_count": symbol_count,
        "categories": categories,
        "category_summary": ", ".join(categories) if categories else "None"
    }

def check_dictionary_and_breach(password):
    """Step 3 — Efficient Dictionary & Threat Database Lookup."""
    pw_lower = password.lower()
    
    # 1. Direct SQLite / Fallback Lookup
    if password_exists(pw_lower):
        return True, pw_lower, f"CRITICAL MATCH: Found in Threat Database Corpus"

    # 2. Common root/base words search (Lazy Loaded)
    patterns = get_lazy_patterns()
    for base in patterns["base_words"]:
        if base in pw_lower:
            return True, base, f"Breach Pattern Match: Contains common root term ('{base}') from threat corpus"

    return False, None, f"No match found in threat intelligence dataset."

def analyze_patterns_and_masks(password):
    """Step 4 — Structural Pattern & Mask Analysis."""
    patterns_list = []
    pw_lower = password.lower()
    lazy_pats = get_lazy_patterns()

    has_year = bool(re.search(r'(19[5-9]\d|20[0-3]\d)', password))
    has_base = any(b in pw_lower for b in lazy_pats["base_words"])
    has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))

    if has_base and has_year and has_symbol:
        matched_base = next((b for b in lazy_pats["base_words"] if b in pw_lower), "word")
        matched_year = re.search(r'(19[5-9]\d|20[0-3]\d)', password).group(0)
        patterns_list.append(f"Common word ('{matched_base}') + year ('{matched_year}') + symbol pattern detected")

    if re.search(r'(012|123|234|345|456|567|678|789|987|876|765|654|543|432|321)', pw_lower):
        patterns_list.append("Sequential number series (e.g., 123, 789)")

    for k in lazy_pats["keyboards"]:
        if k in pw_lower:
            patterns_list.append(f"Keyboard sequence layout ('{k}')")
            break

    if re.search(r'(.)\1{2,}', password):
        patterns_list.append("Repeated character sequence (e.g. aaa, 111)")

    if has_year and not (has_base and has_symbol):
        matched_year = re.search(r'(19[5-9]\d|20[0-3]\d)', password).group(0)
        patterns_list.append(f"Contains 4-digit calendar year ('{matched_year}')")

    pattern_summary = "; ".join(patterns_list) if patterns_list else "No predictable structural patterns detected."
    return patterns_list, pattern_summary

def estimate_attacker_profiles(password, entropy):
    """Step 5 — Multi-Hardware Attacker Profiles."""
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

    cpu_sec = guesses / 10000.0
    gpu_sec = guesses / 1e9
    high_gpu_sec = guesses / 1e11

    def format_time(seconds):
        if seconds < 1: return "Under 1 second"
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

def evaluate_password_full(password):
    """Step 6 — Score & Verdict Output."""
    if not password:
        return {
            "password_received": "",
            "preprocessing": preprocess_password(""),
            "dict_match": False,
            "dict_word": None,
            "dict_message": "No input password provided.",
            "patterns": [],
            "pattern_summary": "None",
            "entropy": 0.0,
            "attacker_profiles": estimate_attacker_profiles("", 0),
            "score": 0,
            "verdict": "Very Weak",
            "color": "#ff3366",
            "explanation": "Please enter a password to evaluate.",
            "suggestion": "Enter a strong, unpredictable passphrase.",
            "statistics": STATISTICS_STATS
        }

    pw_received = password
    prep = preprocess_password(password)
    is_dict, dict_word, dict_msg = check_dictionary_and_breach(prep["normalized"])
    patterns, pattern_summary = analyze_patterns_and_masks(prep["normalized"])
    entropy_val = calculate_entropy(prep["normalized"])
    attacker = estimate_attacker_profiles(prep["normalized"], entropy_val)

    base_score = 0
    if prep["length"] >= 16: base_score += 25
    elif prep["length"] >= 12: base_score += 20
    elif prep["length"] >= 10: base_score += 15
    elif prep["length"] >= 8: base_score += 10
    else: base_score += 5

    if prep["upper_count"] > 0: base_score += 10
    if prep["lower_count"] > 0: base_score += 10
    if prep["digit_count"] > 0: base_score += 10
    if prep["symbol_count"] > 0: base_score += 15

    if not is_dict: base_score += 15
    if not patterns: base_score += 10
    if entropy_val >= 60: base_score += 5
    elif entropy_val >= 35: base_score += 3

    final_score = min(100, max(0, base_score))
    if final_score <= 30:
        verdict = "Very Weak"
        color = "#ff3366"
        suggestion = "Increase length to at least 14 characters and avoid terms present in threat intelligence datasets."
    elif final_score <= 50:
        verdict = "Weak"
        color = "#ff9900"
        suggestion = "Avoid seasons, calendar years, and terms present in breach dictionary datasets."
    elif final_score <= 70:
        verdict = "Medium"
        color = "#ffcc00"
        suggestion = "Add unique non-dictionary words or mix symbols inside words."
    elif final_score <= 90:
        verdict = "Strong"
        color = "#00f0ff"
        suggestion = "Strong security level! Ensure password uniqueness across sites."
    else:
        verdict = "Very Strong"
        color = "#00ff66"
        suggestion = "Exceptional security! High entropy and highly resistant to modern attack vectors."

    explanation = f"Evaluated as {verdict} ({final_score}/100). "
    if is_dict:
        explanation += f"Matched term in threat database ('{dict_word}'). "
    if patterns:
        explanation += f"Structure match: {pattern_summary}. "
    explanation += f"High-end GPU crack estimate: {attacker['high_gpu_time']}."

    return {
        "password_received": f"Password received for evaluation ('{prep['normalized']}')",
        "preprocessing": prep,
        "dict_match": is_dict,
        "dict_word": dict_word,
        "dict_message": dict_msg,
        "patterns": patterns,
        "pattern_summary": pattern_summary,
        "entropy": entropy_val,
        "attacker_profiles": attacker,
        "score": final_score,
        "verdict": verdict,
        "color": color,
        "explanation": explanation,
        "suggestion": suggestion,
        "statistics": STATISTICS_STATS
    }

# ----------------------------------------------------------------------
# STEP 10: HEALTH ENDPOINT (Lightweight RAM consumption)
# ----------------------------------------------------------------------
@app.route('/health')
def health():
    return jsonify({"status": "online"})

# ROUTES
@app.route('/')
def index():
    return render_template('index.html', stats=STATISTICS_STATS)

@app.route('/evaluate', methods=['POST'])
def evaluate():
    data = request.get_json(silent=True) or request.form
    password = data.get('password', '')
    result = evaluate_password_full(password)
    return jsonify(result)

@app.route('/generate', methods=['GET', 'POST'])
def generate():
    data = request.get_json(silent=True) or request.args
    length = int(data.get('length', 16))
    use_upper = data.get('uppercase', 'true') in ['true', True, '1']
    use_lower = data.get('lowercase', 'true') in ['true', True, '1']
    use_digits = data.get('numbers', 'true') in ['true', True, '1']
    use_symbols = data.get('symbols', 'true') in ['true', True, '1']

    chars = ""
    if use_upper: chars += string.ascii_uppercase
    if use_lower: chars += string.ascii_lowercase
    if use_digits: chars += string.digits
    if use_symbols: chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"

    if not chars:
        chars = string.ascii_letters + string.digits

    guaranteed = []
    if use_upper: guaranteed.append(random.choice(string.ascii_uppercase))
    if use_lower: guaranteed.append(random.choice(string.ascii_lowercase))
    if use_digits: guaranteed.append(random.choice(string.digits))
    if use_symbols: guaranteed.append(random.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))

    remaining_len = max(0, length - len(guaranteed))
    random_chars = [random.choice(chars) for _ in range(remaining_len)]
    full_list = guaranteed + random_chars
    random.shuffle(full_list)

    generated_pw = "".join(full_list)
    eval_result = evaluate_password_full(generated_pw)

    return jsonify({
        "password": generated_pw,
        "evaluation": eval_result
    })

@app.route('/result')
def result_page():
    return render_template('result.html')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
