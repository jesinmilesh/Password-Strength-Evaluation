import os
import random
import string
from flask import Flask, render_template, request, jsonify, g
import attack_engine

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cyber_shield_threat_intelligence_2026')

STATISTICS_STATS = {
    "password_corpus": "30+ Million",
    "dictionary_lists": "2",
    "keyboard_patterns": "500+",
    "names": "100,000",
    "common_words": "370,000"
}

@app.teardown_appcontext
def close_db_connection(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# ----------------------------------------------------------------------
# ROUTES & ENDPOINTS
# ----------------------------------------------------------------------
@app.route('/health')
def health():
    return jsonify({"status": "online"})

@app.route('/')
def index():
    return render_template('index.html', stats=STATISTICS_STATS)

@app.route('/evaluate', methods=['POST'])
def evaluate():
    data = request.get_json(silent=True) or request.form
    password = data.get('password', '')
    result = attack_engine.evaluate_password_workflow(password)
    result["statistics"] = STATISTICS_STATS
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
    eval_result = attack_engine.evaluate_password_workflow(generated_pw)
    eval_result["statistics"] = STATISTICS_STATS

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
