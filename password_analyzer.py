import os
import re
import math
import time
import webbrowser
import string
import hashlib
import secrets
from functools import lru_cache
from flask import Flask, request, jsonify, send_from_directory, render_template_string

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()

# Common passwords and patterns
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345", "12345678",
    "1234567", "123123", "qwerty", "111111", "abc123",
    "password1", "admin", "welcome", "monkey", "login",
    "letmein", "sunshine", "master", "hello", "football",
    "iloveyou", "princess", "rockyou", "solo", "starwars",
    "whatever", "dragon", "passw0rd", "trustno1", "access",
    "shadow", "superman", "batman", "jordan", "harley",
    "matrix", "buster", "hunter", "thomas", "ginger",
    "1qaz2wsx", "1q2w3e4r", "qazwsx", "asdfgh", "zxcvbn",
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "!@#$%^&*", "qwerty123",
    "2000", "2001", "2010", "2011", "2020", "2021", "2022", "2023",
    "1990", "1991", "1992", "1993", "1994", "1995", "1996", "1997",
    "1998", "1999", "2002", "2003", "2004", "2005", "2006", "2007",
    "2008", "2009", "2012", "2013", "2014", "2015", "2016", "2017",
    "2018", "2019", "2024", "2025", "toronto", "paris", "nyc", "london",
    "tokyo", "moscow", "berlin", "losangeles", "shanghai", "beijing",
    "yankees", "liverpool", "chelsea", "arsenal", "baseball",
    "soccer", "hockey", "basketball", "football", "running",
    "pokemon", "samsung", "iphone", "google", "michelle",
    "andrea", "nicole", "jennifer", "ashley", "amanda",
    "aaaaaa", "zzzzzz", "abcdef", "abcabc", "a1b2c3",
    "aa123456", "654321", "123abc", "1234abcd", "1234qwer",
    "changeme", "secret", "password123", "welcome123", "admin123",
    "temp", "guest", "default", "pass", "pw"
}

KEYBOARD_PATTERNS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "qwerty", "asdfgh", "zxcvbn",
    "1234567890", "qazwsx", "wsxedc", "qazwsxedc", "1qaz2wsx", "3edc4rfv",
    "12345qwert", "qwert12345", "zxcvbasdf", "qweasdzxc"
]

SEQUENTIAL_PATTERNS = [
    "abcdefghijklmnopqrstuvwxyz", "zyxwvutsrqponmlkjihgfedcba",
    "0123456789", "9876543210"
]

# Names of months and days (for pattern detection)
MONTHS = ["january", "february", "march", "april", "may", "june", "july",
          "august", "september", "october", "november", "december"]
DAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]

# Names of common services (for pattern detection)
SERVICES = ["gmail", "yahoo", "hotmail", "facebook", "twitter", "instagram",
            "linkedin", "snapchat", "tiktok", "reddit", "amazon", "netflix",
            "spotify", "apple", "google", "microsoft", "github", "outlook",
            "wechat", "excel", "youtube", "discord", "zoom", "teams", "skype"]

# Entropy and scoring thresholds
ENTROPY_THRESHOLD = {
    "very_weak": 40,
    "weak": 60,
    "medium": 80,
    "strong": 100,
    "very_strong": 120
}

# Crack time thresholds in seconds
CRACK_TIME_THRESHOLD = {
    "very_weak": 60,             # 1 minute
    "weak": 86400,               # 1 day
    "medium": 2592000,           # 30 days
    "strong": 31536000,          # 1 year
    "very_strong": 3153600000    # 100 years
}

# Cracking speeds (guesses per second)
CRACKING_SPEEDS = {
    "online_throttled": 100,            # Online service with throttling
    "online_unthrottled": 10000,        # Online service without throttling
    "offline_slow_hash": 10000000,      # Offline attack with slow hash (bcrypt)
    "offline_fast_hash": 1000000000,    # Offline attack with fast hash (MD5)
    "offline_gpu_attack": 10000000000   # Offline attack with GPU acceleration
}

# Feature weights for ML-based scoring
FEATURE_WEIGHTS = {
    "length": 0.25,
    "entropy": 0.25,
    "character_set_complexity": 0.2,
    "pattern_penalty": 0.2,
    "common_password_penalty": 0.1
}

# Breach detection - simulated prefixes of hashed passwords
BREACH_HASH_PREFIXES = {
    "5BAA6": True,  # hash of "password"
    "E38AD": True,  # hash of "123456"
    "D8578": True,  # hash of "qwerty"
    "5F4DC": True,  # hash of "welcome"
    "7C222": True,  # hash of "iloveyou"
    "C1572": True,  # hash of "sunshine"
    "0B14D": True,  # hash of "monkey"
    "F6F2E": True,  # hash of "dragon"
    "670B1": True,  # hash of "football"
    "D0199": True   # hash of "baseball"
}

# Password strength analyzer class
class PasswordStrengthAnalyzer:
    def __init__(self):
        self.result = {}

    @lru_cache(maxsize=1024)
    def analyze(self, password):
        """Analyze password strength and return comprehensive results"""
        if not password:
            return self._get_empty_result()

        # Basic statistics
        length = len(password)
        char_stats = self._get_character_stats(password)

        # Calculate entropy and complexity
        entropy = self._calculate_entropy(password, char_stats)
        complexity = self._calculate_complexity(password, char_stats)

        # Pattern detection
        patterns = self._detect_patterns(password)

        # Breach detection
        is_breached = self._check_breach(password)

        # Time to crack
        crack_times = self._calculate_crack_times(entropy)

        # Strength score
        strength_score = self._calculate_strength_score(
            password, length, entropy, complexity, patterns, is_breached
        )

        # Suggestions
        suggestions = self._generate_suggestions(
            password, length, char_stats, patterns, is_breached
        )

        # Results
        result = {
            "password": self._mask_password(password),
            "strength": {
                "score": strength_score,
                "category": self._get_strength_category(strength_score),
                "entropy_bits": round(entropy, 2),
                "complexity": complexity
            },
            "statistics": {
                "length": length,
                "characters": char_stats
            },
            "vulnerabilities": {
                "patterns_found": patterns,
                "is_common": password.lower() in COMMON_PASSWORDS,
                "is_breached": is_breached
            },
            "crack_times": crack_times,
            "suggestions": suggestions
        }

        self.result = result
        return result

    def _get_empty_result(self):
        """Return an empty result object"""
        return {
            "password": "",
            "strength": {
                "score": 0,
                "category": "very_weak",
                "entropy_bits": 0,
                "complexity": 0
            },
            "statistics": {
                "length": 0,
                "characters": {
                    "lowercase": 0,
                    "uppercase": 0,
                    "digits": 0,
                    "special": 0,
                    "unique": 0
                }
            },
            "vulnerabilities": {
                "patterns_found": [],
                "is_common": False,
                "is_breached": False
            },
            "crack_times": {
                "online_throttled": 0,
                "online_unthrottled": 0,
                "offline_slow_hash": 0,
                "offline_fast_hash": 0,
                "offline_gpu_attack": 0
            },
            "suggestions": ["Please enter a password"]
        }

    def _mask_password(self, password):
        """Mask the password for display"""
        if len(password) <= 2:
            return "*" * len(password)
        return password[0] + "*" * (len(password) - 2) + password[-1]

    def _get_character_stats(self, password):
        """Get statistics about character usage"""
        stats = {
            "lowercase": sum(1 for c in password if c.islower()),
            "uppercase": sum(1 for c in password if c.isupper()),
            "digits": sum(1 for c in password if c.isdigit()),
            "special": sum(1 for c in password if c in string.punctuation),
            "unique": len(set(password))
        }
        return stats

    def _calculate_entropy(self, password, char_stats):
        """Calculate password entropy (bits)"""
        # Calculate the size of the character pool
        char_pool_size = 0
        if char_stats["lowercase"] > 0:
            char_pool_size += 26
        if char_stats["uppercase"] > 0:
            char_pool_size += 26
        if char_stats["digits"] > 0:
            char_pool_size += 10
        if char_stats["special"] > 0:
            char_pool_size += 33  # Approximate number of special characters

        # If no characters were found (unlikely), default to 1
        if char_pool_size == 0:
            char_pool_size = 1

        # Basic entropy calculation: log2(char_pool_size^length)
        basic_entropy = len(password) * math.log2(char_pool_size)

        # Adjust for patterns, repetitions, and other factors
        adjustments = self._calculate_entropy_adjustments(password)

        return max(0, basic_entropy + adjustments)

    def _calculate_entropy_adjustments(self, password):
        """Calculate adjustments to entropy based on patterns"""
        adjustments = 0

        # Penalize repeated characters
        char_counts = {}
        for char in password:
            char_counts[char] = char_counts.get(char, 0) + 1

        for char, count in char_counts.items():
            if count > 1:
                # Penalize multiple occurrences of the same character
                adjustments -= count * 0.2

        # Penalize sequential patterns
        for pattern in SEQUENTIAL_PATTERNS:
            for i in range(len(pattern) - 2):
                seq = pattern[i:i+3].lower()
                if seq in password.lower():
                    adjustments -= 2

        # Penalize keyboard patterns
        for pattern in KEYBOARD_PATTERNS:
            for i in range(len(pattern) - 2):
                seq = pattern[i:i+3].lower()
                if seq in password.lower():
                    adjustments -= 2

        # Penalize common words
        for word in COMMON_PASSWORDS:
            if len(word) >= 4 and word in password.lower():
                adjustments -= len(word) * 0.5

        # Penalize dates
        date_pattern = re.compile(r'\d{4}|\d{2}[/.-]\d{2}[/.-]\d{2,4}')
        if date_pattern.search(password):
            adjustments -= 5

        return adjustments

    def _calculate_complexity(self, password, char_stats):
        """Calculate password complexity score (0-100)"""
        # Calculate base complexity based on character types
        types_used = sum(1 for val in char_stats.values() if val > 0)
        base_complexity = types_used * 25  # 25 points per character type

        # Adjust for length
        length_factor = min(1, len(password) / 12)  # Normalize to 12 characters

        # Adjust for uniqueness
        uniqueness_factor = char_stats["unique"] / len(password)

        return min(100, base_complexity * length_factor * uniqueness_factor)

    def _detect_patterns(self, password):
        """Detect common patterns in the password"""
        patterns = []
        password_lower = password.lower()

        # Check for keyboard patterns
        for pattern in KEYBOARD_PATTERNS:
            if len(pattern) >= 4 and pattern in password_lower:
                patterns.append({"type": "keyboard", "pattern": pattern})

        # Check for sequential patterns
        for pattern in SEQUENTIAL_PATTERNS:
            for i in range(len(pattern) - 2):
                seq = pattern[i:i+3]
                if seq in password_lower:
                    patterns.append({"type": "sequential", "pattern": seq})
                    break

        # Check for repeated characters
        for i in range(len(password) - 2):
            if password[i] == password[i+1] == password[i+2]:
                patterns.append({"type": "repeated", "pattern": password[i]*3})

        # Check for common words
        for word in COMMON_PASSWORDS:
            if len(word) >= 4 and word in password_lower:
                patterns.append({"type": "common_word", "pattern": word})

        # Check for dates
        date_pattern = re.compile(r'\d{4}|\d{2}[/.-]\d{2}[/.-]\d{2,4}')
        match = date_pattern.search(password)
        if match:
            patterns.append({"type": "date", "pattern": match.group()})

        # Check for months and days
        for month in MONTHS:
            if month in password_lower:
                patterns.append({"type": "month", "pattern": month})

        for day in DAYS:
            if day in password_lower:
                patterns.append({"type": "day", "pattern": day})

        # Check for service names
        for service in SERVICES:
            if service in password_lower:
                patterns.append({"type": "service", "pattern": service})

        return patterns

    def _check_breach(self, password):
        """Check if password appears in known breaches"""
        hash_obj = hashlib.sha1(password.encode('utf-8'))
        hash_hex = hash_obj.hexdigest().upper()
        hash_prefix = hash_hex[:5]

        return hash_prefix in BREACH_HASH_PREFIXES

    def _calculate_crack_times(self, entropy):
        """Calculate estimated time to crack for different scenarios"""
        crack_times = {}

        for speed_name, guesses_per_second in CRACKING_SPEEDS.items():
            # Formula: 2^entropy / guesses_per_second
            guesses_needed = 2 ** entropy
            seconds_to_crack = guesses_needed / guesses_per_second
            crack_times[speed_name] = seconds_to_crack

        return crack_times

    def _calculate_strength_score(self, password, length, entropy, complexity, patterns, is_breached):
        """Calculate password strength score using weighted features"""
        # Base score from entropy (0-100)
        entropy_score = min(100, entropy * 1.2)

        # Length score (0-100)
        length_score = min(100, length * 5)

        # Character set complexity score (already 0-100)
        complexity_score = complexity

        # Pattern penalty (0-100, lower is better)
        pattern_penalty = min(100, len(patterns) * 20)

        # Common password penalty (0-100, lower is better)
        common_penalty = 100 if password.lower() in COMMON_PASSWORDS or is_breached else 0

        # Apply weights
        weighted_score = (
                FEATURE_WEIGHTS["length"] * length_score +
                FEATURE_WEIGHTS["entropy"] * entropy_score +
                FEATURE_WEIGHTS["character_set_complexity"] * complexity_score +
                FEATURE_WEIGHTS["pattern_penalty"] * (100 - pattern_penalty) +
                FEATURE_WEIGHTS["common_password_penalty"] * (100 - common_penalty)
        )

        return round(weighted_score)

    def _get_strength_category(self, score):
        """Convert numerical score to strength category"""
        if score >= 90:
            return "very_strong"
        elif score >= 70:
            return "strong"
        elif score >= 50:
            return "medium"
        elif score >= 30:
            return "weak"
        else:
            return "very_weak"

    def _generate_suggestions(self, password, length, char_stats, patterns, is_breached):
        """Generate suggestions to improve the password"""
        suggestions = []

        # Length suggestions
        if length < 8:
            suggestions.append("Make your password at least 8 characters long")
        elif length < 12:
            suggestions.append("Consider using a longer password (12+ characters)")

        # Character variety suggestions
        if char_stats["lowercase"] == 0:
            suggestions.append("Add lowercase letters")
        if char_stats["uppercase"] == 0:
            suggestions.append("Add uppercase letters")
        if char_stats["digits"] == 0:
            suggestions.append("Add numbers")
        if char_stats["special"] == 0:
            suggestions.append("Add special characters (e.g., !@#$%^&*)")

        # Pattern suggestions
        pattern_types = set(p["type"] for p in patterns)

        if "keyboard" in pattern_types or "sequential" in pattern_types:
            suggestions.append("Avoid keyboard patterns like 'qwerty' or sequential characters like '123456'")

        if "repeated" in pattern_types:
            suggestions.append("Avoid repeating characters like 'aaa' or '111'")

        if "common_word" in pattern_types:
            suggestions.append("Avoid common words like 'password' or 'welcome'")

        if "date" in pattern_types or "month" in pattern_types or "day" in pattern_types:
            suggestions.append("Avoid using dates, months, or days in your password")

        if "service" in pattern_types:
            suggestions.append("Avoid using service names like 'facebook' or 'gmail'")

        # Breach suggestions
        if is_breached:
            suggestions.append("This password has appeared in data breaches. Please choose a different one")

        # General suggestions
        if len(suggestions) == 0:
            if length < 16:
                suggestions.append("For even stronger security, use a longer password")
            elif length >= 16:
                suggestions.append("Your password is already quite strong. Consider using a password manager")

        return suggestions

# Create an instance of the analyzer
analyzer = PasswordStrengthAnalyzer()

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/analyze', methods=['POST'])
def analyze_password():
    data = request.get_json()
    password = data.get('password', '')
    result = analyzer.analyze(password)

    # Simulate ML processing delay for larger passwords
    if len(password) > 10:
        time.sleep(0.1)

    return jsonify(result)

@app.route('/generate', methods=['GET'])
def generate_password():
    """Generate a strong password"""
    length = request.args.get('length', 16, type=int)
    length = max(8, min(64, length))  # Ensure length is between 8 and 64

    # Ensure we have at least one of each character type
    chars = []
    chars.append(secrets.choice(string.ascii_lowercase))
    chars.append(secrets.choice(string.ascii_uppercase))
    chars.append(secrets.choice(string.digits))
    chars.append(secrets.choice(string.punctuation))

    # Fill the rest with random characters
    for i in range(length - 4):
        chars.append(secrets.choice(
            string.ascii_lowercase +
            string.ascii_uppercase +
            string.digits +
            string.punctuation
        ))

    # Shuffle the characters and join them
    secrets.SystemRandom().shuffle(chars)
    password = ''.join(chars)

    return jsonify({'password': password})

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

# HTML template for the web interface
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced Password Security Analyzer</title>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary-color: #3498db;
            --secondary-color: #2ecc71;
            --danger-color: #e74c3c;
            --warning-color: #f39c12;
            --dark-color: #2c3e50;
            --light-color: #ecf0f1;
            --grey-color: #95a5a6;
            --transition-speed: 0.3s;
            
            /* Strength colors */
            --very-weak-color: #d32f2f;
            --weak-color: #f57c00;
            --medium-color: #fbc02d;
            --strong-color: #7cb342;
            --very-strong-color: #388e3c;
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: 'Roboto', sans-serif;
            line-height: 1.6;
            color: var(--dark-color);
            background-color: #f5f5f5;
            padding: 20px;
        }
        
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background-color: white;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }
        
        header {
            background-color: var(--primary-color);
            color: white;
            padding: 20px;
            text-align: center;
        }
        
        h1 {
            margin-bottom: 10px;
            font-size: 28px;
        }
        
        .subtitle {
            font-size: 16px;
            opacity: 0.9;
        }
        
        .main-content {
            padding: 30px;
        }
        
        .password-input-container {
            position: relative;
            margin-bottom: 30px;
        }
        
        .password-input {
            width: 100%;
            padding: 15px;
            font-size: 18px;
            border: 2px solid var(--grey-color);
            border-radius: 5px;
            transition: border-color var(--transition-speed);
        }
        
        .password-input:focus {
            outline: none;
            border-color: var(--primary-color);
        }
        
        .toggle-password {
            position: absolute;
            right: 15px;
            top: 50%;
            transform: translateY(-50%);
            cursor: pointer;
            color: var(--grey-color);
            font-size: 14px;
            padding: 5px;
            background: none;
            border: none;
        }
        
        .toggle-password:hover {
            color: var(--primary-color);
        }
        
        .password-actions {
            display: flex;
            justify-content: space-between;
            margin-bottom: 30px;
        }
        
        .generate-btn {
            background-color: var(--primary-color);
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            transition: background-color var(--transition-speed);
        }
        
        .generate-btn:hover {
            background-color: #2980b9;
        }
        
        .clear-btn {
            background-color: var(--grey-color);
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            transition: background-color var(--transition-speed);
        }
        
        .clear-btn:hover {
            background-color: #7f8c8d;
        }
        
        .results {
            display: none;
            margin-top: 20px;
        }
        
        .result-section {
            margin-bottom: 30px;
        }
        
        .section-title {
            font-size: 18px;
            margin-bottom: 15px;
            color: var(--dark-color);
            font-weight: 500;
        }
        
        /* Strength meter */
        .strength-meter {
            height: 10px;
            background-color: #ddd;
            border-radius: 5px;
            margin-bottom: 10px;
            overflow: hidden;
        }
        
        .strength-meter-fill {
            height: 100%;
            width: 0;
            transition: width 0.5s ease-in-out, background-color 0.5s ease-in-out;
        }
        
        .strength-category {
            font-size: 16px;
            font-weight: bold;
            margin-bottom: 15px;
        }
        
        /* Statistics */
        .stats-container {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .stat-box {
            background-color: #f5f5f5;
            border-radius: 5px;
            padding: 15px;
            width: calc(50% - 10px);
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.05);
        }
        
        .stat-title {
            font-size: 14px;
            margin-bottom: 5px;
        }
        
        .stat-value {
            font-size: 24px;
            font-weight: bold;
            color: var(--primary-color);
        }
        
        /* Crack times */
        .crack-times {
            background-color: var(--light-color);
            border-radius: 5px;
            padding: 20px;
            margin-bottom: 20px;
        }
        
        .crack-time-item {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
            padding-bottom: 10px;
            border-bottom: 1px solid #ddd;
        }
        
        .crack-time-item:last-child {
            border-bottom: none;
            margin-bottom: 0;
            padding-bottom: 0;
        }
        
        .crack-time-label {
            font-weight: 500;
        }
        
        .crack-time-value {
            font-family: monospace;
        }
        
        /* Vulnerabilities */
        .vulnerabilities {
            background-color: #fff;
            border-radius: 5px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid #ddd;
        }
        
        .vulnerability-item {
            display: flex;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .vulnerability-icon {
            margin-right: 10px;
            width: 20px;
            height: 20px;
            border-radius: 50%;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 12px;
            font-weight: bold;
        }
        
        .icon-danger {
            background-color: var(--danger-color);
        }
        
        .icon-warning {
            background-color: var(--warning-color);
        }
        
        .icon-success {
            background-color: var(--secondary-color);
        }
        
        /* Suggestions */
        .suggestions {
            background-color: #fff;
            border-radius: 5px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid #ddd;
        }
        
        .suggestion-list {
            list-style-type: none;
        }
        
        .suggestion-item {
            margin-bottom: 10px;
            padding-left: 25px;
            position: relative;
        }
        
        .suggestion-item:before {
            content: "→";
            position: absolute;
            left: 0;
            color: var(--primary-color);
        }
        
        /* Character breakdown */
        .char-breakdown {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 15px;
        }
        
        .char-type {
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 12px;
            color: white;
        }
        
        .char-lowercase {
            background-color: #3498db;
        }
        
        .char-uppercase {
            background-color: #2980b9;
        }
        
        .char-digit {
            background-color: #e74c3c;
        }
        
        .char-special {
            background-color: #9b59b6;
        }
        
        .char-unique {
            background-color: #2ecc71;
        }
        
        /* Visualization */
        .visualization-container {
            margin-top: 30px;
            padding: 20px;
            background-color: #f9f9f9;
            border-radius: 5px;
        }
        
        .visualization-title {
            margin-bottom: 15px;
            font-weight: 500;
        }
        
        .visualization-info {
            font-size: 14px;
            color: var(--grey-color);
            margin-bottom: 20px;
        }
.patterns-found {
            margin-top: 20px;
        }
        
        .pattern-badge {
            display: inline-block;
            margin: 5px;
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 12px;
            background-color: #f8f9fa;
            border: 1px solid #e9ecef;
        }
        
        /* Responsive design */
        @media (max-width: 768px) {
            .stat-box {
                width: 100%;
            }
            
            .main-content {
                padding: 15px;
            }
        }
        
        /* Loading animation */
        .loading {
            display: none;
            text-align: center;
            padding: 20px;
        }
        
        .spinner {
            border: 4px solid rgba(0, 0, 0, 0.1);
            width: 36px;
            height: 36px;
            border-radius: 50%;
            border-left-color: var(--primary-color);
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        /* Footer */
        footer {
            text-align: center;
            padding: 20px;
            color: var(--grey-color);
            font-size: 14px;
            background-color: #f5f5f5;
            border-top: 1px solid #ddd;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Advanced Password Security Analyzer</h1>
            <p class="subtitle">Check and improve your password strength with detailed analysis</p>
        </header>
        
        <div class="main-content">
            <div class="password-input-container">
                <input type="password" id="password-input" class="password-input" placeholder="Enter your password">
                <button class="toggle-password" id="toggle-password">Show</button>
            </div>
            
            <div class="password-actions">
                <button id="generate-password" class="generate-btn">Generate Strong Password</button>
                <button id="clear-password" class="clear-btn">Clear</button>
            </div>
            
            <div id="loading" class="loading">
                <div class="spinner"></div>
                <p>Analyzing password...</p>
            </div>
            
            <div id="results" class="results">
                <div class="result-section">
                    <h2 class="section-title">Password Strength</h2>
                    <div class="strength-meter">
                        <div id="strength-meter-fill" class="strength-meter-fill"></div>
                    </div>
                    <div id="strength-category" class="strength-category"></div>
                </div>
                
                <div class="result-section">
                    <h2 class="section-title">Statistics</h2>
                    <div class="stats-container">
                        <div class="stat-box">
                            <div class="stat-title">Length</div>
                            <div id="length-value" class="stat-value">0</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-title">Entropy</div>
                            <div id="entropy-value" class="stat-value">0</div>
                            <div class="stat-subtitle">bits</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-title">Complexity</div>
                            <div id="complexity-value" class="stat-value">0</div>
                            <div class="stat-subtitle">out of 100</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-title">Character Types</div>
                            <div id="char-breakdown" class="char-breakdown"></div>
                        </div>
                    </div>
                </div>
                
                <div class="result-section">
                    <h2 class="section-title">Time to Crack</h2>
                    <div class="crack-times">
                        <div class="crack-time-item">
                            <span class="crack-time-label">Online Attack (Throttled)</span>
                            <span id="crack-time-throttled" class="crack-time-value">-</span>
                        </div>
                        <div class="crack-time-item">
                            <span class="crack-time-label">Online Attack (No Throttling)</span>
                            <span id="crack-time-unthrottled" class="crack-time-value">-</span>
                        </div>
                        <div class="crack-time-item">
                            <span class="crack-time-label">Offline Attack (Slow Hash)</span>
                            <span id="crack-time-slow-hash" class="crack-time-value">-</span>
                        </div>
                        <div class="crack-time-item">
                            <span class="crack-time-label">Offline Attack (Fast Hash)</span>
                            <span id="crack-time-fast-hash" class="crack-time-value">-</span>
                        </div>
                        <div class="crack-time-item">
                            <span class="crack-time-label">Offline Attack (GPU)</span>
                            <span id="crack-time-gpu" class="crack-time-value">-</span>
                        </div>
                    </div>
                </div>
                
                <div class="result-section">
                    <h2 class="section-title">Vulnerabilities</h2>
                    <div class="vulnerabilities">
                        <div class="vulnerability-item">
                            <div id="common-password-icon" class="vulnerability-icon icon-success">✓</div>
                            <span id="common-password-text">Not a common password</span>
                        </div>
                        <div class="vulnerability-item">
                            <div id="breach-icon" class="vulnerability-icon icon-success">✓</div>
                            <span id="breach-text">Not found in known data breaches</span>
                        </div>
                        <div id="patterns-container" class="patterns-found">
                            <h3>Patterns Detected:</h3>
                            <div id="patterns-list"></div>
                        </div>
                    </div>
                </div>
                
                <div class="result-section">
                    <h2 class="section-title">Suggestions</h2>
                    <div class="suggestions">
                        <ul id="suggestion-list" class="suggestion-list"></ul>
                    </div>
                </div>
                
                <div class="visualization-container">
                    <h2 class="visualization-title">About Password Security</h2>
                    <p class="visualization-info">
                        Strong passwords are your first line of defense against unauthorized access to your accounts.
                        This tool analyzes various aspects of your password including its complexity, patterns,
                        and vulnerability to different types of attacks.
                    </p>
                    <p class="visualization-info">
                        For maximum security, use a unique password for each account, enable two-factor authentication
                        when available, and consider using a password manager to create and store complex passwords.
                    </p>
                </div>
            </div>
        </div>
        
        <footer>
            <p>This tool is for educational purposes only and does not store any passwords.</p>
        </footer>
    </div>
    
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const passwordInput = document.getElementById('password-input');
            const togglePasswordBtn = document.getElementById('toggle-password');
            const generatePasswordBtn = document.getElementById('generate-password');
            const clearPasswordBtn = document.getElementById('clear-password');
            const resultsContainer = document.getElementById('results');
            const loadingContainer = document.getElementById('loading');
            
            // Strength meter elements
            const strengthMeterFill = document.getElementById('strength-meter-fill');
            const strengthCategory = document.getElementById('strength-category');
            
            // Statistics elements
            const lengthValue = document.getElementById('length-value');
            const entropyValue = document.getElementById('entropy-value');
            const complexityValue = document.getElementById('complexity-value');
            const charBreakdown = document.getElementById('char-breakdown');
            
            // Crack time elements
            const crackTimeThrottled = document.getElementById('crack-time-throttled');
            const crackTimeUnthrottled = document.getElementById('crack-time-unthrottled');
            const crackTimeSlowHash = document.getElementById('crack-time-slow-hash');
            const crackTimeFastHash = document.getElementById('crack-time-fast-hash');
            const crackTimeGpu = document.getElementById('crack-time-gpu');
            
            // Vulnerability elements
            const commonPasswordIcon = document.getElementById('common-password-icon');
            const commonPasswordText = document.getElementById('common-password-text');
            const breachIcon = document.getElementById('breach-icon');
            const breachText = document.getElementById('breach-text');
            const patternsList = document.getElementById('patterns-list');
            const patternsContainer = document.getElementById('patterns-container');
            
            // Suggestions element
            const suggestionList = document.getElementById('suggestion-list');
            
            // Toggle password visibility
            togglePasswordBtn.addEventListener('click', function() {
                if (passwordInput.type === 'password') {
                    passwordInput.type = 'text';
                    togglePasswordBtn.textContent = 'Hide';
                } else {
                    passwordInput.type = 'password';
                    togglePasswordBtn.textContent = 'Show';
                }
            });
            
            // Generate password
            generatePasswordBtn.addEventListener('click', function() {
                const length = 16; // Default length
                fetch(`/generate?length=${length}`)
                    .then(response => response.json())
                    .then(data => {
                        passwordInput.value = data.password;
                        passwordInput.type = 'text';
                        togglePasswordBtn.textContent = 'Hide';
                        analyzePassword();
                    });
            });
            
            // Clear password
            clearPasswordBtn.addEventListener('click', function() {
                passwordInput.value = '';
                resultsContainer.style.display = 'none';
            });
            
            // Analyze password when input changes
            let debounceTimer;
            passwordInput.addEventListener('input', function() {
                clearTimeout(debounceTimer);
                debounceTimer = setTimeout(analyzePassword, 500);
            });
            
            // Format time duration in human-readable format
            function formatTimeDuration(seconds) {
                if (seconds < 0.001) {
                    return 'Instantly';
                }
                if (seconds < 1) {
                    return `${Math.round(seconds * 1000)} milliseconds`;
                }
                if (seconds < 60) {
                    return `${Math.round(seconds)} seconds`;
                }
                if (seconds < 3600) {
                    return `${Math.round(seconds / 60)} minutes`;
                }
                if (seconds < 86400) {
                    return `${Math.round(seconds / 3600)} hours`;
                }
                if (seconds < 2592000) {
                    return `${Math.round(seconds / 86400)} days`;
                }
                if (seconds < 31536000) {
                    return `${Math.round(seconds / 2592000)} months`;
                }
                if (seconds < 3153600000) {
                    return `${Math.round(seconds / 31536000)} years`;
                }
                return 'Centuries';
            }
            
            // Set strength meter color based on category
            function setStrengthMeterColor(category, score) {
                switch(category) {
                    case 'very_weak':
                        strengthMeterFill.style.backgroundColor = 'var(--very-weak-color)';
                        break;
                    case 'weak':
                        strengthMeterFill.style.backgroundColor = 'var(--weak-color)';
                        break;
                    case 'medium':
                        strengthMeterFill.style.backgroundColor = 'var(--medium-color)';
                        break;
                    case 'strong':
                        strengthMeterFill.style.backgroundColor = 'var(--strong-color)';
                        break;
                    case 'very_strong':
                        strengthMeterFill.style.backgroundColor = 'var(--very-strong-color)';
                        break;
                }
                strengthMeterFill.style.width = `${score}%`;
            }
            
            // Format strength category for display
            function formatStrengthCategory(category) {
                switch(category) {
                    case 'very_weak':
                        return 'Very Weak';
                    case 'weak':
                        return 'Weak';
                    case 'medium':
                        return 'Medium';
                    case 'strong':
                        return 'Strong';
                    case 'very_strong':
                        return 'Very Strong';
                    default:
                        return 'Unknown';
                }
            }
            
            // Analyze password and update UI
            function analyzePassword() {
                const password = passwordInput.value;
                
                if (!password) {
                    resultsContainer.style.display = 'none';
                    return;
                }
                
                // Show loading
                loadingContainer.style.display = 'block';
                resultsContainer.style.display = 'none';
                
                fetch('/analyze', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ password })
                })
                .then(response => response.json())
                .then(data => {
                    // Hide loading, show results
                    loadingContainer.style.display = 'none';
                    resultsContainer.style.display = 'block';
                    
                    // Update strength meter
                    setStrengthMeterColor(data.strength.category, data.strength.score);
                    strengthCategory.textContent = `${formatStrengthCategory(data.strength.category)} (${data.strength.score}/100)`;
                    
                    // Update statistics
                    lengthValue.textContent = data.statistics.length;
                    entropyValue.textContent = data.strength.entropy_bits;
                    complexityValue.textContent = data.strength.complexity;
                    
                    // Update character breakdown
                    charBreakdown.innerHTML = '';
                    if (data.statistics.characters.lowercase > 0) {
                        const element = document.createElement('span');
                        element.className = 'char-type char-lowercase';
                        element.textContent = `${data.statistics.characters.lowercase} lowercase`;
                        charBreakdown.appendChild(element);
                    }
                    
                    if (data.statistics.characters.uppercase > 0) {
                        const element = document.createElement('span');
                        element.className = 'char-type char-uppercase';
                        element.textContent = `${data.statistics.characters.uppercase} uppercase`;
                        charBreakdown.appendChild(element);
                    }
                    
                    if (data.statistics.characters.digits > 0) {
                        const element = document.createElement('span');
                        element.className = 'char-type char-digit';
                        element.textContent = `${data.statistics.characters.digits} digits`;
                        charBreakdown.appendChild(element);
                    }
                    
                    if (data.statistics.characters.special > 0) {
                        const element = document.createElement('span');
                        element.className = 'char-type char-special';
                        element.textContent = `${data.statistics.characters.special} special`;
                        charBreakdown.appendChild(element);
                    }
                    
                    const uniqueElement = document.createElement('span');
                    uniqueElement.className = 'char-type char-unique';
                    uniqueElement.textContent = `${data.statistics.characters.unique} unique`;
                    charBreakdown.appendChild(uniqueElement);
                    
                    // Update crack times
                    crackTimeThrottled.textContent = formatTimeDuration(data.crack_times.online_throttled);
                    crackTimeUnthrottled.textContent = formatTimeDuration(data.crack_times.online_unthrottled);
                    crackTimeSlowHash.textContent = formatTimeDuration(data.crack_times.offline_slow_hash);
                    crackTimeFastHash.textContent = formatTimeDuration(data.crack_times.offline_fast_hash);
                    crackTimeGpu.textContent = formatTimeDuration(data.crack_times.offline_gpu_attack);
                    
                    // Update vulnerabilities
                    if (data.vulnerabilities.is_common) {
                        commonPasswordIcon.className = 'vulnerability-icon icon-danger';
                        commonPasswordIcon.textContent = '!';
                        commonPasswordText.textContent = 'Common password detected';
                    } else {
                        commonPasswordIcon.className = 'vulnerability-icon icon-success';
                        commonPasswordIcon.textContent = '✓';
                        commonPasswordText.textContent = 'Not a common password';
                    }
                    
                    if (data.vulnerabilities.is_breached) {
                        breachIcon.className = 'vulnerability-icon icon-danger';
                        breachIcon.textContent = '!';
                        breachText.textContent = 'Found in known data breaches';
                    } else {
                        breachIcon.className = 'vulnerability-icon icon-success';
                        breachIcon.textContent = '✓';
                        breachText.textContent = 'Not found in known data breaches';
                    }
                    
                    // Update patterns
                    patternsList.innerHTML = '';
                    if (data.vulnerabilities.patterns_found.length > 0) {
                        patternsContainer.style.display = 'block';
                        data.vulnerabilities.patterns_found.forEach(pattern => {
                            const patternBadge = document.createElement('span');
                            patternBadge.className = 'pattern-badge';
                            patternBadge.textContent = `${pattern.type}: ${pattern.pattern}`;
                            patternsList.appendChild(patternBadge);
                        });
                    } else {
                        patternsContainer.style.display = 'none';
                    }
                    
                    // Update suggestions
                    suggestionList.innerHTML = '';
                    data.suggestions.forEach(suggestion => {
                        const suggestionItem = document.createElement('li');
                        suggestionItem.className = 'suggestion-item';
                        suggestionItem.textContent = suggestion;
                        suggestionList.appendChild(suggestionItem);
                    });
                })
                .catch(error => {
                    console.error('Error:', error);
                    loadingContainer.style.display = 'none';
                    alert('An error occurred while analyzing the password.');
                });
            }
        });
    </script>
</body>
</html>
'''

if __name__ == '__main__':
    url = "http://127.0.0.1:5000/"
    print(f"Dash app is running. If the browser does not open automatically, click here: {url}")
    webbrowser.open(url)
    app.run(debug=False)
