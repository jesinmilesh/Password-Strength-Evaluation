import os
import re

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASETS_DIR = os.path.join(BASE_DIR, 'datasets')

# Cache for lazy loading patterns
_CACHED_PATTERNS = None

def get_pattern_data():
    global _CACHED_PATTERNS
    if _CACHED_PATTERNS is not None:
        return _CACHED_PATTERNS

    names_set = set()
    keyboards_set = set()
    years_set = set()

    # Load names
    names_path = os.path.join(DATASETS_DIR, 'names.txt')
    if os.path.exists(names_path):
        with open(names_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                n = line.strip().lower()
                if n and len(n) >= 3:
                    names_set.add(n)

    # Load keyboard patterns
    kb_path = os.path.join(DATASETS_DIR, 'keyboard_patterns.txt')
    if os.path.exists(kb_path):
        with open(kb_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                k = line.strip().lower()
                if k:
                    keyboards_set.add(k)

    # Default fallback keyboard walks if file missing/empty
    if not keyboards_set:
        keyboards_set = {'qwerty', 'asdfgh', 'zxcvbn', '1q2w3e', '123456', '987654', 'qwert', 'asdf'}

    # Load years
    yr_path = os.path.join(DATASETS_DIR, 'years.txt')
    if os.path.exists(yr_path):
        with open(yr_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                y = line.strip()
                if y:
                    years_set.add(y)

    _CACHED_PATTERNS = {
        "names": names_set,
        "keyboards": keyboards_set,
        "years": years_set
    }
    return _CACHED_PATTERNS

def normalize_leetspeak(text):
    """Convert common leetspeak characters back to standard letters."""
    leet_map = {
        '@': 'a', '4': 'a',
        '3': 'e',
        '1': 'i', '!': 'i', '|': 'i',
        '0': 'o',
        '$': 's', '5': 's',
        '7': 't', '+': 't'
    }
    normalized = text.lower()
    for symbol, letter in leet_map.items():
        normalized = normalized.replace(symbol, letter)
    return normalized

def detect_patterns(password):
    """
    Step 4 – Pattern & Mask Analysis Engine
    Detects Word+Year, Keyboard Walks, Sequential Numbers, Names, Leetspeak, Repeated Chars.
    Returns: (list of risk objects, pattern summary string)
    """
    if not password:
        return [], "No input password provided."

    data = get_pattern_data()
    detected_risks = []
    pw_lower = password.lower()
    pw_leet = normalize_leetspeak(password)

    # 1. Year detection (1999–2035)
    year_match = re.search(r'(19[9]\d|20[0-3]\d)', password)
    detected_year = year_match.group(0) if year_match else None

    # 2. Base dictionary word & Name detection
    base_words = ['summer', 'winter', 'spring', 'autumn', 'season', 'password', 'admin', 'qwerty', 'welcome', 'cyber', 'shield', 'dragon', 'princess', 'monkey', 'charlie', 'sunshine', 'google', 'matrix', 'crypto']
    matched_base = next((b for b in base_words if b in pw_lower or b in pw_leet), None)
    
    matched_name = next((n for n in data["names"] if n in pw_lower or n in pw_leet), None)

    has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))

    # 3. Word + Year / Name + Year Combination
    if (matched_base or matched_name) and detected_year:
        word_found = matched_base.capitalize() if matched_base else matched_name.capitalize()
        if has_symbol:
            detected_risks.append({
                "type": "Word + Year",
                "label": f"Common Word ('{word_found}') + Year ('{detected_year}') + Symbol",
                "severity": "high"
            })
        else:
            detected_risks.append({
                "type": "Word + Year",
                "label": f"Word / Name ('{word_found}') + Year ('{detected_year}') Combination",
                "severity": "high"
            })

    # 4. Standalone Name Detection
    if matched_name and not (matched_base and detected_year):
        detected_risks.append({
            "type": "Name Mask",
            "label": f"Contains Common First Name ('{matched_name.capitalize()}')",
            "severity": "medium"
        })

    # 5. Keyboard Walks (e.g. qwerty, asdfgh, 1q2w3e)
    for kb in data["keyboards"]:
        if kb in pw_lower or kb in pw_leet:
            detected_risks.append({
                "type": "Keyboard Walk",
                "label": f"Keyboard Sequence Layout ('{kb}')",
                "severity": "high"
            })
            break

    # 6. Sequential Numbers (e.g. 123456, 7890, 9876)
    if re.search(r'(012|123|234|345|456|567|678|789|987|876|765|654|543|432|321)', pw_lower):
        detected_risks.append({
            "type": "Sequential Series",
            "label": "Sequential Number Series (e.g., 123, 789)",
            "severity": "medium"
        })

    # 7. Repeated Characters (e.g. aaaa, 1111)
    if re.search(r'(.)\1{2,}', password):
        detected_risks.append({
            "type": "Repeated Pattern",
            "label": "Repeated Character Sequence (e.g. aaa, 111)",
            "severity": "medium"
        })

    # 8. Leetspeak Transformation Detection
    if pw_leet != pw_lower and (matched_base or matched_name or "password" in pw_leet):
        detected_risks.append({
            "type": "Leetspeak Mask",
            "label": "Predictable Leetspeak Character Substitution (e.g. @ for a, 3 for e)",
            "severity": "medium"
        })

    # 9. Standalone Year
    if detected_year and not (matched_base or matched_name):
        detected_risks.append({
            "type": "Calendar Year",
            "label": f"Contains 4-digit Calendar Year ('{detected_year}')",
            "severity": "medium"
        })

    labels = [r["label"] for r in detected_risks]
    pattern_summary = "; ".join(labels) if labels else "No predictable structural patterns detected."
    
    return detected_risks, pattern_summary
