#!/usr/bin/env python3

import hashlib
import hmac
import secrets
import time
import itertools
import string
import json
import os
import sys
from datetime import datetime

# ─────────────────────────────────────────────────────────────
# COLOUR HELPERS  (terminal output)
# ─────────────────────────────────────────────────────────────
class Colors:
    RED    = '\033[91m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    BLUE   = '\033[94m'
    CYAN   = '\033[96m'
    WHITE  = '\033[97m'
    BOLD   = '\033[1m'
    RESET  = '\033[0m'

def cprint(text, color=Colors.WHITE):
    print(f"{color}{text}{Colors.RESET}")

# ─────────────────────────────────────────────────────────────
# HASHING  FUNCTIONS
# ─────────────────────────────────────────────────────────────
SUPPORTED_ALGORITHMS = ['md5', 'sha1', 'sha256', 'sha512']

def hash_password(password: str, algorithm: str = 'md5') -> str:
    """Hash a plain-text password using the specified algorithm."""
    algo = algorithm.lower()
    if algo not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm. Choose from: {SUPPORTED_ALGORITHMS}")
    h = hashlib.new(algo)
    h.update(password.encode('utf-8'))
    return h.hexdigest()

def hash_password_salted(password: str, salt: str = '', algorithm: str = 'sha256') -> str:
    """Hash a password with a salt (simulates secure storage)."""
    salted = salt + password
    return hash_password(salted, algorithm)

def generate_salt(length: int = 16) -> str:
    """Generate a cryptographically random salt."""
    return secrets.token_hex(length)

# ─────────────────────────────────────────────────────────────
# ATTACK  ENGINES
# ─────────────────────────────────────────────────────────────

def dictionary_attack(target_hash: str, wordlist: list, algorithm: str = 'md5') -> dict:
    """
    Dictionary Attack – tries every word in a wordlist.
    Most common and effective attack against real-world passwords.
    """
    cprint(f"\n[*] Starting Dictionary Attack | Algorithm: {algorithm.upper()}", Colors.CYAN)
    cprint(f"    Wordlist size : {len(wordlist)} entries", Colors.WHITE)
    cprint(f"    Target hash   : {target_hash[:32]}...", Colors.WHITE)

    start = time.time()
    attempts = 0

    for word in wordlist:
        candidate_hash = hash_password(word, algorithm)
        attempts += 1
        if candidate_hash == target_hash:
            elapsed = time.time() - start
            cprint(f"\n[+] PASSWORD CRACKED: '{word}'", Colors.GREEN)
            cprint(f"    Attempts : {attempts} | Time: {elapsed:.4f}s", Colors.GREEN)
            return {"status": "cracked", "password": word, "attempts": attempts, "time": elapsed}

    elapsed = time.time() - start
    cprint(f"\n[-] Dictionary attack failed after {attempts} attempts ({elapsed:.4f}s)", Colors.RED)
    return {"status": "failed", "attempts": attempts, "time": elapsed}


def brute_force_attack(target_hash: str, max_length: int = 4,
                       charset: str = string.ascii_lowercase + string.digits,
                       algorithm: str = 'md5') -> dict:
    """
    Brute-Force Attack – tries every possible combination up to max_length.
    Guaranteed to crack any password given enough time.
    """
    cprint(f"\n[*] Starting Brute-Force Attack | Algorithm: {algorithm.upper()}", Colors.CYAN)
    cprint(f"    Max length : {max_length} | Charset size: {len(charset)}", Colors.WHITE)
    cprint(f"    Target hash: {target_hash[:32]}...", Colors.WHITE)

    start = time.time()
    attempts = 0
    total_combinations = sum(len(charset)**l for l in range(1, max_length + 1))
    cprint(f"    Total combinations: {total_combinations:,}", Colors.WHITE)

    for length in range(1, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            candidate = ''.join(combo)
            candidate_hash = hash_password(candidate, algorithm)
            attempts += 1
            if candidate_hash == target_hash:
                elapsed = time.time() - start
                cprint(f"\n[+] PASSWORD CRACKED: '{candidate}'", Colors.GREEN)
                cprint(f"    Attempts : {attempts:,} | Time: {elapsed:.4f}s", Colors.GREEN)
                return {"status": "cracked", "password": candidate, "attempts": attempts, "time": elapsed}

    elapsed = time.time() - start
    cprint(f"\n[-] Brute-force failed after {attempts:,} attempts ({elapsed:.4f}s)", Colors.RED)
    return {"status": "failed", "attempts": attempts, "time": elapsed}


def mask_attack(target_hash: str, masks: list, algorithm: str = 'md5') -> dict:
    """
    Mask Attack – uses pattern-based generation.
    ?l = lowercase, ?u = uppercase, ?d = digit, ?s = special.
    e.g. "?u?l?l?l?d?d?d" matches 'Pass123'
    """
    cprint(f"\n[*] Starting Mask Attack | Algorithm: {algorithm.upper()}", Colors.CYAN)

    MASK_CHARS = {
        '?l': string.ascii_lowercase,
        '?u': string.ascii_uppercase,
        '?d': string.digits,
        '?s': string.punctuation,
        '?a': string.ascii_letters + string.digits + string.punctuation,
    }

    start = time.time()
    total_attempts = 0

    for mask in masks:
        cprint(f"    Trying mask: {mask}", Colors.WHITE)
        # Parse mask into char sets
        i = 0
        char_sets = []
        while i < len(mask):
            if mask[i] == '?' and i + 1 < len(mask):
                token = mask[i:i+2]
                if token in MASK_CHARS:
                    char_sets.append(MASK_CHARS[token])
                    i += 2
                    continue
            char_sets.append([mask[i]])
            i += 1

        for combo in itertools.product(*char_sets):
            candidate = ''.join(combo)
            candidate_hash = hash_password(candidate, algorithm)
            total_attempts += 1
            if candidate_hash == target_hash:
                elapsed = time.time() - start
                cprint(f"\n[+] PASSWORD CRACKED: '{candidate}'  (mask: {mask})", Colors.GREEN)
                cprint(f"    Attempts : {total_attempts:,} | Time: {elapsed:.4f}s", Colors.GREEN)
                return {"status": "cracked", "password": candidate, "attempts": total_attempts, "time": elapsed}

    elapsed = time.time() - start
    cprint(f"\n[-] Mask attack failed after {total_attempts:,} attempts ({elapsed:.4f}s)", Colors.RED)
    return {"status": "failed", "attempts": total_attempts, "time": elapsed}


def rule_based_attack(target_hash: str, base_words: list, algorithm: str = 'md5') -> dict:
    """
    Rule-Based Attack – applies transformation rules to base words.
    Rules: append numbers, capitalise, leet substitutions, common suffixes.
    """
    cprint(f"\n[*] Starting Rule-Based Attack | Algorithm: {algorithm.upper()}", Colors.CYAN)

    def apply_rules(word):
        variants = set()
        variants.add(word)
        variants.add(word.capitalize())
        variants.add(word.upper())
        variants.add(word.lower())
        # Leet substitutions
        leet = word.replace('a','@').replace('e','3').replace('i','1').replace('o','0').replace('s','$')
        variants.add(leet)
        variants.add(leet.capitalize())
        # Common suffixes
        for suffix in ['1','123','!','@','2024','2025','#1','99','007','!@#']:
            variants.add(word + suffix)
            variants.add(word.capitalize() + suffix)
            variants.add(leet + suffix)
        # Reverse
        variants.add(word[::-1])
        return variants

    start = time.time()
    attempts = 0

    for base in base_words:
        for candidate in apply_rules(base):
            candidate_hash = hash_password(candidate, algorithm)
            attempts += 1
            if candidate_hash == target_hash:
                elapsed = time.time() - start
                cprint(f"\n[+] PASSWORD CRACKED: '{candidate}'  (base: '{base}')", Colors.GREEN)
                cprint(f"    Attempts : {attempts:,} | Time: {elapsed:.4f}s", Colors.GREEN)
                return {"status": "cracked", "password": candidate, "attempts": attempts, "time": elapsed}

    elapsed = time.time() - start
    cprint(f"\n[-] Rule-based attack failed after {attempts:,} attempts ({elapsed:.4f}s)", Colors.RED)
    return {"status": "failed", "attempts": attempts, "time": elapsed}


# ─────────────────────────────────────────────────────────────
# PASSWORD  STRENGTH  ANALYSER
# ─────────────────────────────────────────────────────────────
def analyse_password_strength(password: str) -> dict:
    """Evaluate password strength and return a detailed report."""
    score = 0
    feedback = []

    has_lower   = any(c.islower() for c in password)
    has_upper   = any(c.isupper() for c in password)
    has_digit   = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    length      = len(password)

    if length >= 8:  score += 1
    if length >= 12: score += 1; feedback.append("Good length (12+)")
    if length >= 16: score += 1; feedback.append("Excellent length (16+)")
    if has_lower:    score += 1
    if has_upper:    score += 1; feedback.append("Contains uppercase")
    if has_digit:    score += 1; feedback.append("Contains digits")
    if has_special:  score += 2; feedback.append("Contains special characters")

    # Penalise common patterns
    common = ['password','123456','qwerty','abc','admin','letmein','welcome']
    if any(c in password.lower() for c in common):
        score -= 2
        feedback.append("WARNING: Contains common pattern — very weak")

    if length < 8:
        feedback.append("Too short — minimum 8 characters recommended")

    if score <= 2:   strength = "Very Weak"
    elif score <= 4: strength = "Weak"
    elif score <= 6: strength = "Moderate"
    elif score <= 8: strength = "Strong"
    else:            strength = "Very Strong"

    return {
        "password":       password,
        "length":         length,
        "score":          score,
        "strength":       strength,
        "has_lowercase":  has_lower,
        "has_uppercase":  has_upper,
        "has_digits":     has_digit,
        "has_special":    has_special,
        "feedback":       feedback
    }


# ─────────────────────────────────────────────────────────────
# DEMO  DATASET
# ─────────────────────────────────────────────────────────────
SAMPLE_PASSWORDS = [
    {"user": "alice",   "password": "password123", "note": "Very common password"},
    {"user": "bob",     "password": "qwerty",       "note": "Keyboard pattern"},
    {"user": "charlie", "password": "abc123",       "note": "Simple combination"},
    {"user": "diana",   "password": "P@ssw0rd",     "note": "Common leet substitution"},
    {"user": "eve",     "password": "dragon",       "note": "Common dictionary word"},
    {"user": "frank",   "password": "123456",       "note": "Numeric only"},
    {"user": "grace",   "password": "iloveyou",     "note": "Common phrase"},
    {"user": "henry",   "password": "Tr0ub4dor&3",  "note": "Strong passphrase-style"},
    {"user": "iris",    "password": "correct horse battery staple", "note": "Long passphrase — strongest"},
    {"user": "james",   "password": "admin",        "note": "Default admin credential"},
]

WORDLIST = [
    "password", "123456", "password123", "admin", "letmein",
    "welcome", "monkey", "dragon", "master", "sunshine",
    "qwerty", "abc123", "iloveyou", "batman", "superman",
    "football", "shadow", "pass", "login", "password1",
    "hello", "charlie", "donald", "princess", "jordan",
    "harley", "ranger", "solo", "cheese", "freedom",
    "whatever", "lovely", "trustno1", "diamond", "pass123",
    "baseball", "soccer", "hockey", "andrew", "jessica",
    "pepper", "mustang", "michael", "testing", "robert",
    # Some leet/rule variants
    "p@ssword", "P@ssw0rd", "passw0rd", "pa$$word", "p4ssword",
    "qwerty123", "abc@123", "eve", "dragon1", "iloveyou1",
]

# ─────────────────────────────────────────────────────────────
# REPORTING
# ─────────────────────────────────────────────────────────────
def generate_report(results: list, output_file: str = "crack_report.json"):
    """Save cracking results to a JSON report."""
    report = {
        "tool":      "Hashcat Password Security Simulator",
        "team":      ["Gauri Deshmukh (1601023124)",
                      "Girish Chaudhari (16010123125)",
                      "Gurkaran Singh Ahuja (16010123129)"],
        "course":    "NIS IA#2 - TY B.Tech Jan-Apr 2026",
        "timestamp": datetime.now().isoformat(),
        "results":   results,
    }
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    cprint(f"\n[*] Report saved → {output_file}", Colors.BLUE)


# ─────────────────────────────────────────────────────────────
# MAIN  DEMO
# ─────────────────────────────────────────────────────────────
def banner():
    cprint("""
╔══════════════════════════════════════════════════════════════╗
║         HASHCAT PASSWORD SECURITY SIMULATOR                  ║
║  NIS IA#2 — TY B.Tech (Jan–Apr 2026)                        ║
║  Team: Gauri Deshmukh | Girish Chaudhari | Gurkaran Ahuja   ║
╚══════════════════════════════════════════════════════════════╝
    """, Colors.CYAN)

def section(title):
    cprint(f"\n{'='*64}", Colors.BLUE)
    cprint(f"  {title}", Colors.BOLD + Colors.YELLOW)
    cprint(f"{'='*64}", Colors.BLUE)


def run_full_demo():
    banner()
    all_results = []

    # ── SECTION 1: Hash Generation Demo ──────────────────────
    section("1. HASH GENERATION — Sample Dataset")
    cprint("Generating MD5, SHA1, SHA256, SHA512 hashes for sample passwords...\n", Colors.WHITE)
    hash_table = []
    for entry in SAMPLE_PASSWORDS:
        pwd = entry["password"]
        row = {
            "user":    entry["user"],
            "password": pwd,
            "note":    entry["note"],
            "md5":     hash_password(pwd, 'md5'),
            "sha1":    hash_password(pwd, 'sha1'),
            "sha256":  hash_password(pwd, 'sha256'),
            "sha512":  hash_password(pwd, 'sha512'),
        }
        hash_table.append(row)
        cprint(f"  [{entry['user']:8s}] {pwd:35s} → MD5: {row['md5'][:16]}...", Colors.WHITE)

    # ── SECTION 2: Password Strength Analysis ─────────────────
    section("2. PASSWORD STRENGTH ANALYSIS")
    strength_results = []
    for entry in SAMPLE_PASSWORDS:
        analysis = analyse_password_strength(entry["password"])
        strength_results.append(analysis)
        bar_fill  = "█" * min(analysis["score"], 10)
        bar_empty = "░" * (10 - min(analysis["score"], 10))
        color = (Colors.RED if analysis["strength"] in ("Very Weak","Weak")
                 else Colors.YELLOW if analysis["strength"] == "Moderate"
                 else Colors.GREEN)
        cprint(f"  {entry['password']:35s} [{bar_fill}{bar_empty}] {analysis['strength']}", color)

    # ── SECTION 3: Dictionary Attack ──────────────────────────
    section("3. DICTIONARY ATTACK — MD5 Hashes")
    dict_results = []
    targets_dict = [p for p in SAMPLE_PASSWORDS if p["password"] in WORDLIST][:3]
    for target in targets_dict:
        h = hash_password(target["password"], 'md5')
        cprint(f"\n  Target user: {target['user']} | Hash: {h[:24]}...", Colors.WHITE)
        result = dictionary_attack(h, WORDLIST, 'md5')
        result["user"] = target["user"]
        dict_results.append(result)

    # ── SECTION 4: Brute Force Attack ─────────────────────────
    section("4. BRUTE-FORCE ATTACK — Short numeric password")
    cprint("  (Testing '1234' → MD5 hash)", Colors.WHITE)
    target_bf = hash_password("1234", 'md5')
    bf_result = brute_force_attack(target_bf, max_length=4,
                                   charset=string.digits, algorithm='md5')

    # ── SECTION 5: Mask Attack ────────────────────────────────
    section("5. MASK ATTACK — Pattern-based")
    # Testing 'abc123' pattern: 3 lowercase + 3 digits
    target_mask = hash_password("abc123", 'md5')
    masks = ["?l?l?l?d?d?d"]
    mask_result = mask_attack(target_mask, masks, 'md5')

    # ── SECTION 6: Rule-Based Attack ─────────────────────────
    section("6. RULE-BASED ATTACK — Transformations on base words")
    target_rule = hash_password("P@ssw0rd", 'md5')
    base_words   = ["password", "pass", "admin", "letmein", "dragon"]
    rule_result  = rule_based_attack(target_rule, base_words, 'md5')

    # ── SECTION 7: Salted vs Unsalted Demo ───────────────────
    section("7. SALTED vs UNSALTED HASHING — Security Comparison")
    test_pwd = "password123"
    unsalted = hash_password(test_pwd, 'sha256')
    salt1    = generate_salt()
    salt2    = generate_salt()
    salted1  = hash_password_salted(test_pwd, salt1, 'sha256')
    salted2  = hash_password_salted(test_pwd, salt2, 'sha256')

    cprint(f"\n  Password     : {test_pwd}", Colors.WHITE)
    cprint(f"  Unsalted SHA256 : {unsalted}", Colors.RED)
    cprint(f"  Salt 1          : {salt1}", Colors.YELLOW)
    cprint(f"  Salted  SHA256  : {salted1}", Colors.GREEN)
    cprint(f"  Salt 2          : {salt2}", Colors.YELLOW)
    cprint(f"  Salted  SHA256  : {salted2}", Colors.GREEN)
    cprint("\n  ✓ Same password → different salted hashes (defeats rainbow tables!)", Colors.GREEN)

    # ── SECTION 8: Summary ────────────────────────────────────
    section("8. SUMMARY & SECURITY RECOMMENDATIONS")
    cracked_count = sum(1 for r in dict_results if r["status"] == "cracked")
    cracked_count += (1 if bf_result["status"] == "cracked" else 0)
    cracked_count += (1 if mask_result["status"] == "cracked" else 0)
    cracked_count += (1 if rule_result["status"] == "cracked" else 0)

    cprint(f"\n  Passwords tested : {len(SAMPLE_PASSWORDS)}", Colors.WHITE)
    cprint(f"  Cracked          : {cracked_count}", Colors.RED if cracked_count > 0 else Colors.GREEN)
    cprint(f"\n  RECOMMENDATIONS:", Colors.YELLOW)
    cprint("  ✓ Use passwords of 12+ characters with mixed case, numbers & symbols", Colors.GREEN)
    cprint("  ✓ Never use dictionary words or common patterns", Colors.GREEN)
    cprint("  ✓ Always salt hashes — prevents rainbow table attacks", Colors.GREEN)
    cprint("  ✓ Use strong algorithms: SHA-256/512, bcrypt, Argon2 (NOT MD5/SHA1)", Colors.GREEN)
    cprint("  ✓ Enable Multi-Factor Authentication (MFA) everywhere possible", Colors.GREEN)
    cprint("  ✓ Use a password manager to generate and store unique passwords", Colors.GREEN)

    # ── Save Report ───────────────────────────────────────────
    all_results = {
        "hash_table":      hash_table,
        "strength_analysis": strength_results,
        "dictionary_attack": dict_results,
        "brute_force":     bf_result,
        "mask_attack":     mask_result,
        "rule_based":      rule_result,
    }
    generate_report(all_results)
    cprint("\n[✓] Demo complete!\n", Colors.GREEN + Colors.BOLD)


# ─────────────────────────────────────────────────────────────
# INTERACTIVE  MENU
# ─────────────────────────────────────────────────────────────
def interactive_menu():
    banner()
    while True:
        cprint("\n═══ MENU ═══════════════════════════════════", Colors.BLUE)
        cprint("  1. Hash a custom password", Colors.WHITE)
        cprint("  2. Analyse password strength", Colors.WHITE)
        cprint("  3. Run Dictionary Attack on a hash", Colors.WHITE)
        cprint("  4. Run Brute-Force Attack (digits, max 4)", Colors.WHITE)
        cprint("  5. Run Mask Attack", Colors.WHITE)
        cprint("  6. Run Rule-Based Attack", Colors.WHITE)
        cprint("  7. Run Full Demo (all attacks on sample dataset)", Colors.WHITE)
        cprint("  8. Show sample hashed dataset", Colors.WHITE)
        cprint("  0. Exit", Colors.WHITE)
        cprint("═════════════════════════════════════════════", Colors.BLUE)
        choice = input(f"{Colors.CYAN}  Enter choice: {Colors.RESET}").strip()

        if choice == '1':
            pwd  = input("  Password: ")
            algo = input("  Algorithm (md5/sha1/sha256/sha512) [sha256]: ").strip() or 'sha256'
            print(f"  Hash ({algo.upper()}): {hash_password(pwd, algo)}")

        elif choice == '2':
            pwd = input("  Password to analyse: ")
            r   = analyse_password_strength(pwd)
            cprint(f"\n  Strength : {r['strength']}  (score {r['score']})", Colors.YELLOW)
            for fb in r['feedback']:
                cprint(f"  • {fb}", Colors.WHITE)

        elif choice == '3':
            h    = input("  Target MD5 hash: ").strip()
            algo = input("  Algorithm [md5]: ").strip() or 'md5'
            dictionary_attack(h, WORDLIST, algo)

        elif choice == '4':
            h = input("  Target MD5 hash (digits, ≤4 chars): ").strip()
            brute_force_attack(h, max_length=4, charset=string.digits, algorithm='md5')

        elif choice == '5':
            h    = input("  Target MD5 hash: ").strip()
            mask = input("  Mask (e.g. ?l?l?l?d?d?d): ").strip()
            mask_attack(h, [mask], 'md5')

        elif choice == '6':
            h     = input("  Target MD5 hash: ").strip()
            words = input("  Base words (comma-separated): ").split(',')
            rule_based_attack(h, [w.strip() for w in words], 'md5')

        elif choice == '7':
            run_full_demo()

        elif choice == '8':
            section("SAMPLE HASHED DATASET")
            for e in SAMPLE_PASSWORDS:
                h = hash_password(e["password"], 'md5')
                cprint(f"  {e['user']:8s} | {e['password']:35s} | MD5: {h}", Colors.WHITE)

        elif choice == '0':
            cprint("\nExiting. Stay secure! 🔐\n", Colors.GREEN)
            break
        else:
            cprint("  Invalid choice.", Colors.RED)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == '--demo':
        run_full_demo()
    else:
        interactive_menu()
