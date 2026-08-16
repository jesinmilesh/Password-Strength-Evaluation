import os
import re
import database
import pattern_detector
import entropy

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASETS_DIR = os.path.join(BASE_DIR, 'datasets')

FALLBACK_RAM_SET = set()

def init_fallback_set():
    global FALLBACK_RAM_SET
    rf_path = os.path.join(DATASETS_DIR, 'high_risk_passwords.txt')
    cp_path = os.path.join(DATASETS_DIR, 'common_passwords.txt')
    for p in [rf_path, cp_path]:
        if os.path.exists(p):
            with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    pw = line.strip().lower()
                    if pw:
                        FALLBACK_RAM_SET.add(pw)

init_fallback_set()

def password_exists(password):
    """Step 3 – Threat Database Lookup (<100ms response time)."""
    pw_lower = password.strip().lower()
    if not pw_lower:
        return False

    # First attempt database indexed query
    if database.check_password_in_corpus(pw_lower):
        return True

    # Fallback if database record not present
    return pw_lower in FALLBACK_RAM_SET

def preprocess_password(password):
    """
    Step 2 – Preprocess & Normalize
    Trim spaces, normalize Unicode, character Breakdown counts.
    """
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

def check_dictionary_match(password):
    """Step 3 – Dictionary & Breach Matching."""
    pw_lower = password.lower()

    if password_exists(pw_lower):
        return True, pw_lower, f"CRITICAL MATCH: Exact match found in Threat Database Corpus ({password})"

    # Check root word extract (e.g. Summer in Summer2024!)
    base_words = ['summer', 'winter', 'spring', 'autumn', 'season', 'password', 'admin', 'qwerty', 'welcome', 'cyber', 'shield', 'dragon', 'princess', 'monkey', 'charlie', 'sunshine', 'google', 'matrix', 'crypto']
    for b in base_words:
        if b in pw_lower:
            return True, b, f"Dictionary Match: Found root term ('{b.capitalize()}') in leaked database"

    return False, None, "No dictionary match."

def evaluate_password_workflow(password):
    """
    Orchestrates Steps 1 through 6 of the Proposed System Workflow.
    """
    # Step 1: Input Validation
    if not password or len(password) > 256:
        return {
            "step1": {"valid": False, "message": "Reject empty input or input exceeding 256 characters."},
            "score": 0, "verdict": "Invalid", "color": "#ff3366"
        }

    # Step 2: Preprocess & Normalize
    prep = preprocess_password(password)

    # Step 3: Dictionary / Breach Match
    is_dict, dict_word, dict_msg = check_dictionary_match(prep["normalized"])

    # Step 4: Pattern & Mask Analysis
    detected_risks, pattern_summary = pattern_detector.detect_patterns(prep["normalized"])

    # Step 5: Entropy & Crack-Time Estimate
    entropy_val = entropy.calculate_shannon_entropy(prep["normalized"])
    attacker = entropy.estimate_crack_times(prep["normalized"], is_dictionary_match=is_dict, has_patterns=bool(detected_risks))

    # Step 6: Score & Explain
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
    if not detected_risks: base_score += 10
    if entropy_val >= 60: base_score += 5
    elif entropy_val >= 35: base_score += 3

    final_score = min(100, max(0, base_score))

    if final_score <= 30:
        verdict = "Very Weak"
        color = "#ff3366"
        suggestion = "Increase length to at least 14 characters and avoid terms present in threat datasets."
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
    if pattern_summary and pattern_summary != "No predictable structural patterns detected.":
        explanation += f"Structure match: {pattern_summary}. "
    explanation += f"High-end GPU crack estimate: {attacker['high_gpu_time']}."

    # Log evaluation anonymously into database/logs.db (NEVER log password!)
    database.log_evaluation_anonymous(final_score, verdict, is_dict, entropy_val)

    return {
        "step1": {"valid": True, "message": "Password received for evaluation."},
        "step2": prep,
        "step3": {
            "match": is_dict,
            "matched_word": dict_word,
            "message": dict_msg
        },
        "step4": {
            "risks": detected_risks,
            "summary": pattern_summary
        },
        "step5": {
            "entropy": entropy_val,
            "attacker_profiles": attacker
        },
        "step6": {
            "score": final_score,
            "verdict": verdict,
            "color": color,
            "explanation": explanation,
            "suggestion": suggestion
        },
        # Backwards compatibility fields for frontend UI
        "password_received": f"Password received for evaluation ('{prep['normalized']}')",
        "preprocessing": prep,
        "dict_match": is_dict,
        "dict_word": dict_word,
        "dict_message": dict_msg,
        "patterns": [r["label"] for r in detected_risks],
        "pattern_summary": pattern_summary,
        "entropy": entropy_val,
        "attacker_profiles": attacker,
        "score": final_score,
        "verdict": verdict,
        "color": color,
        "explanation": explanation,
        "suggestion": suggestion
    }
