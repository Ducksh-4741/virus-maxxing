from flask import Flask, render_template, request, redirect, jsonify
import os
import hashlib
import sqlite3
import datetime
import random
import string
import math
import struct
import re

app = Flask(__name__)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
DB_FOLDER = os.path.join(BASE_DIR, "database")
DB_PATH = os.path.join(DB_FOLDER, "database.db")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DB_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # 32 MB

ALLOWED_EXTENSIONS = {
    'exe', 'dll', 'pdf', 'doc', 'docx', 'xls', 'xlsx',
    'zip', 'rar', 'js', 'vbs', 'bat', 'ps1', 'py',
    'sh', 'php', 'html', 'htm', 'txt', 'bin', 'apk',
    'jar', 'class', 'com', 'scr', 'pif', 'cmd'
}

# ─────────────────────────── DATABASE INIT ─────────────────────────── #

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS malware (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_hash TEXT UNIQUE,
        malware_name TEXT,
        category TEXT,
        severity INTEGER
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        sha256 TEXT,
        md5 TEXT,
        result TEXT,
        threat_score INTEGER,
        entropy REAL,
        file_size INTEGER,
        file_type TEXT,
        detection_flags TEXT,
        ip TEXT,
        timestamp TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()

# ─────────────────────────── HELPERS ─────────────────────────── #

def allowed_file(filename):
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    return ext in ALLOWED_EXTENSIONS, ext

def calculate_hashes(file_path):
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), md5.hexdigest()

def calculate_entropy(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    length = len(data)
    for count in freq:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)

def detect_file_type(file_path):
    """Magic-byte based file type detection."""
    magic_signatures = {
        b'MZ': 'PE Executable (EXE/DLL)',
        b'PK\x03\x04': 'ZIP/Office Archive',
        b'%PDF': 'PDF Document',
        b'\x7fELF': 'ELF Executable (Linux)',
        b'\xca\xfe\xba\xbe': 'Java Class File',
        b'ITSF': 'CHM Help File',
        b'\xd0\xcf\x11\xe0': 'MS Office (OLE)',
        b'#!': 'Shell Script',
        b'\x50\x4b\x05\x06': 'Empty ZIP',
        b'Rar!': 'RAR Archive',
        b'\x1f\x8b': 'GZIP Archive',
    }
    try:
        with open(file_path, "rb") as f:
            header = f.read(16)
        for sig, name in magic_signatures.items():
            if header.startswith(sig):
                return name
    except:
        pass
    return "Unknown / Binary"

def detect_file_extension_mismatch(filename, file_path):
    """Check if the file's actual magic bytes match its declared extension."""
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    try:
        with open(file_path, "rb") as f:
            header = f.read(4)
    except:
        return False

    exe_exts = {'exe', 'dll', 'com', 'scr', 'pif'}
    if ext in exe_exts and not header.startswith(b'MZ'):
        return True
    if ext == 'pdf' and not header.startswith(b'%PDF'):
        return True
    if ext in {'zip', 'docx', 'xlsx', 'jar', 'apk'} and not header.startswith(b'PK'):
        return True
    if ext == 'elf' and not header.startswith(b'\x7fELF'):
        return True
    return False

# ─────────────────────────── DETECTION ENGINES ─────────────────────────── #

SUSPICIOUS_KEYWORDS = [
    # Shell & system execution
    ("cmd.exe", 15), ("powershell", 15), ("/bin/sh", 12), ("/bin/bash", 12),
    ("WScript.Shell", 20), ("CreateObject", 15), ("Shell32", 15),
    # Network / C2
    ("socket", 10), ("urllib", 8), ("requests.get", 10), ("wget ", 12),
    ("curl ", 12), ("ftp://", 10), ("http://", 5), ("https://", 3),
    ("connect(", 10), ("bind(", 10), ("listen(", 10), ("recv(", 8),
    # Crypto / ransomware
    ("encrypt", 15), ("decrypt", 10), ("AES", 10), ("RSA", 10),
    ("ransom", 20), ("bitcoin", 15), ("wallet", 10), ("tor2web", 20),
    # Evasion
    ("base64", 8), ("b64decode", 10), ("eval(", 15), ("exec(", 15),
    ("subprocess", 10), ("os.system", 15), ("popen", 12),
    # Registry / persistence
    ("HKEY_", 15), ("RegCreateKey", 15), ("RegSetValue", 15),
    ("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 25),
    # Keylogging / spyware
    ("GetAsyncKeyState", 20), ("SetWindowsHookEx", 20), ("keylogger", 25),
    ("screenshot", 12), ("clipboard", 10),
    # Process injection
    ("VirtualAlloc", 20), ("WriteProcessMemory", 25), ("CreateRemoteThread", 25),
    ("NtUnmapViewOfSection", 25), ("shellcode", 25),
    # Obfuscation patterns
    ("chr(", 8), ("charCodeAt", 8), ("fromCharCode", 12),
    ("String.fromCharCode", 15), ("unescape(", 12),
]

SUSPICIOUS_URL_PATTERNS = [
    r'http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',    # IP-based URLs
    r'\.onion',                                               # Tor domains
    r'bit\.ly|tinyurl|goo\.gl|t\.co',                        # URL shorteners
    r'pastebin\.com',                                         # Paste sites
    r'ngrok\.io',                                             # Tunneling
]

SUSPICIOUS_DOUBLE_EXTENSIONS = [
    '.exe.', '.dll.', '.scr.', '.com.', '.pif.',
    '.bat.', '.cmd.', '.vbs.', '.js.',
]

def keyword_scan(file_path):
    """Scan for known-malicious keywords / strings with weighted scoring."""
    flags = []
    score = 0
    try:
        with open(file_path, "rb") as f:
            content = f.read().decode(errors="ignore")

        for keyword, weight in SUSPICIOUS_KEYWORDS:
            if keyword.lower() in content.lower():
                score += weight
                flags.append(f"Keyword: '{keyword}'")

        for pattern in SUSPICIOUS_URL_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                score += 15
                flags.append(f"Suspicious URL pattern: {pattern}")

    except Exception as e:
        flags.append(f"Read error: {e}")
    return score, flags

def check_double_extension(filename):
    """Detect double-extension tricks like 'invoice.pdf.exe'."""
    for ext in SUSPICIOUS_DOUBLE_EXTENSIONS:
        if ext in filename.lower():
            return 30, f"Double extension detected: '{ext.strip('.')}'"
    return 0, None

def pe_header_analysis(file_path):
    """Basic PE header analysis for EXE/DLL files."""
    score = 0
    flags = []
    try:
        with open(file_path, "rb") as f:
            data = f.read(1024)

        if not data.startswith(b'MZ'):
            return 0, []

        # Find PE offset
        pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
        if pe_offset + 4 > len(data):
            return 0, []

        pe_sig = data[pe_offset:pe_offset+4]
        if pe_sig != b'PE\x00\x00':
            score += 20
            flags.append("Invalid PE signature — possible corruption or packing")
            return score, flags

        # Machine type
        machine = struct.unpack_from('<H', data, pe_offset + 4)[0]
        if machine not in (0x14c, 0x8664, 0x1c0, 0xaa64):
            score += 10
            flags.append(f"Unusual PE machine type: 0x{machine:04X}")

        # Characteristics
        chars = struct.unpack_from('<H', data, pe_offset + 22)[0]
        if chars & 0x2000:  # IMAGE_FILE_DLL
            flags.append("PE type: DLL")
        if chars & 0x0002:  # IMAGE_FILE_EXECUTABLE_IMAGE
            flags.append("PE type: Executable")

        # Timestamp (0 or far-future = suspicious)
        timestamp = struct.unpack_from('<I', data, pe_offset + 8)[0]
        if timestamp == 0:
            score += 10
            flags.append("PE timestamp is zero (stripped/modified)")
        elif timestamp > 2000000000:
            score += 10
            flags.append("PE timestamp is in the far future (anomalous)")

        flags.append(f"PE timestamp: {datetime.datetime.utcfromtimestamp(min(timestamp, 2147483647)).strftime('%Y-%m-%d') if timestamp else 'N/A'}")

    except Exception as e:
        flags.append(f"PE parse error: {e}")
    return score, flags

def obfuscation_detection(file_path):
    """Detect common obfuscation patterns."""
    score = 0
    flags = []
    try:
        with open(file_path, "rb") as f:
            content = f.read().decode(errors="ignore")

        # Long base64-like strings (potential embedded payload)
        b64_matches = re.findall(r'[A-Za-z0-9+/]{200,}={0,2}', content)
        if b64_matches:
            score += 20
            flags.append(f"Long base64-like blob ({len(b64_matches)} found) — possible embedded payload")

        # High hex density
        hex_matches = re.findall(r'(?:\\x[0-9a-fA-F]{2}){10,}', content)
        if hex_matches:
            score += 20
            flags.append(f"Hex-encoded data ({len(hex_matches)} sequences) — possible shellcode")

        # Repeated chr() calls (VBA/JS obfuscation)
        chr_calls = re.findall(r'chr\(\d+\)', content, re.IGNORECASE)
        if len(chr_calls) > 10:
            score += 15
            flags.append(f"chr() obfuscation — {len(chr_calls)} calls detected")

        # Lots of string concatenation (+) often used in JS obfuscation
        plus_count = content.count('"+\"') + content.count("'+'")
        if plus_count > 20:
            score += 10
            flags.append(f"Heavy string concatenation ({plus_count}) — possible JS obfuscation")

    except:
        pass
    return score, flags

def entropy_analysis(entropy, file_ext):
    """Score based on entropy relative to file type expectations."""
    score = 0
    flags = []

    # Archives & compressed files naturally have high entropy
    compressed_types = {'zip', 'rar', 'gz', '7z', 'bz2', 'xz', 'zst'}
    if file_ext in compressed_types:
        return 0, ["High entropy expected for compressed file"]

    if entropy > 7.8:
        score += 35
        flags.append(f"Very high entropy ({entropy}) — likely packed/encrypted binary")
    elif entropy > 7.2:
        score += 20
        flags.append(f"High entropy ({entropy}) — possibly packed or obfuscated")
    elif entropy > 6.5:
        score += 8
        flags.append(f"Moderately elevated entropy ({entropy})")

    return score, flags

def suspicious_filename_check(filename):
    """Flag suspicious filename patterns."""
    score = 0
    flags = []
    lower = filename.lower()

    lure_patterns = [
        'invoice', 'receipt', 'payment', 'order', 'resume', 'cv',
        'document', 'update', 'setup', 'install', 'free', 'crack',
        'keygen', 'patch', 'serial', 'activation', 'license', 'nude',
        'photo', 'video', 'porn', 'xxx',
    ]
    for pattern in lure_patterns:
        if pattern in lower:
            score += 8
            flags.append(f"Lure filename keyword: '{pattern}'")

    # Excessive spaces (hiding real extension)
    if '   ' in filename:
        score += 20
        flags.append("Multiple spaces in filename — possible extension hiding")

    return score, flags

# ─────────────────────────── ROUTES ─────────────────────────── #

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    file = request.files.get("file")
    if not file or not file.filename:
        return redirect("/")

    filename = file.filename
    is_allowed, file_ext = allowed_file(filename)

    # Save file temporarily
    random_name = "".join(random.choices(string.ascii_letters + string.digits, k=16))
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], random_name)
    file.save(file_path)

    file_size = os.path.getsize(file_path)

    # ── Hash computation ──
    sha256, md5 = calculate_hashes(file_path)

    # ── File type detection ──
    detected_type = detect_file_type(file_path)
    entropy = calculate_entropy(file_path)

    # ── Score accumulation ──
    total_score = 0
    all_flags = []

    # 1. DB signature match (highest priority)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM malware WHERE file_hash=?", (sha256,))
    match = c.fetchone()

    if match:
        total_score += 100
        all_flags.append(f"Signature match: {match[2]} ({match[3]}, severity {match[4]})")

    # 2. File extension mismatch
    if detect_file_extension_mismatch(filename, file_path):
        total_score += 35
        all_flags.append("File extension mismatch — declared extension does not match magic bytes")

    # 3. Extension not in allowed list
    if not is_allowed and file_ext:
        total_score += 5
        all_flags.append(f"Unusual extension: .{file_ext}")

    # 4. Keyword scan
    kw_score, kw_flags = keyword_scan(file_path)
    total_score += kw_score
    all_flags.extend(kw_flags)

    # 5. Double extension trick
    de_score, de_flag = check_double_extension(filename)
    if de_flag:
        total_score += de_score
        all_flags.append(de_flag)

    # 6. PE header analysis
    pe_score, pe_flags = pe_header_analysis(file_path)
    total_score += pe_score
    all_flags.extend(pe_flags)

    # 7. Obfuscation detection
    ob_score, ob_flags = obfuscation_detection(file_path)
    total_score += ob_score
    all_flags.extend(ob_flags)

    # 8. Entropy analysis
    ent_score, ent_flags = entropy_analysis(entropy, file_ext)
    total_score += ent_score
    all_flags.extend(ent_flags)

    # 9. Suspicious filename
    fn_score, fn_flags = suspicious_filename_check(filename)
    total_score += fn_score
    all_flags.extend(fn_flags)

    # ── Result classification ──
    if match or total_score >= 80:
        result = "Malicious" if not match else "Malicious (Signature Match)"
        risk_level = "CRITICAL" if total_score >= 100 else "HIGH"
    elif total_score >= 40:
        result = "Suspicious"
        risk_level = "MEDIUM"
    elif total_score >= 15:
        result = "Potentially Unwanted"
        risk_level = "LOW"
    else:
        result = "Safe"
        risk_level = "CLEAN"

    detection_flags_str = " | ".join(all_flags) if all_flags else "No flags"

    # ── Store scan ──
    c.execute("""
        INSERT INTO scans (filename, sha256, md5, result, threat_score, entropy,
                           file_size, file_type, detection_flags, ip, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        filename, sha256, md5, result, total_score, entropy,
        file_size, detected_type, detection_flags_str,
        request.remote_addr, str(datetime.datetime.now())
    ))
    conn.commit()
    conn.close()

    os.remove(file_path)

    return render_template("result.html",
                           filename=filename,
                           sha256=sha256,
                           md5=md5,
                           score=total_score,
                           result=result,
                           risk_level=risk_level,
                           entropy=entropy,
                           file_size=file_size,
                           file_type=detected_type,
                           flags=all_flags)

@app.route("/history")
def history():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 200")
    scans = c.fetchall()
    conn.close()
    return render_template("history.html", scans=scans)

@app.route("/dashboard")
def dashboard():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM scans")
    total = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM scans WHERE result LIKE 'Malicious%'")
    malicious = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM scans WHERE result='Suspicious'")
    suspicious = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM scans WHERE result='Potentially Unwanted'")
    puw = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM scans WHERE result='Safe'")
    safe = c.fetchone()[0]

    c.execute("SELECT AVG(threat_score) FROM scans")
    avg_score = round(c.fetchone()[0] or 0, 1)

    c.execute("SELECT filename, threat_score, result, timestamp FROM scans ORDER BY threat_score DESC LIMIT 5")
    top_threats = c.fetchall()

    c.execute("SELECT file_type, COUNT(*) as cnt FROM scans GROUP BY file_type ORDER BY cnt DESC LIMIT 6")
    file_types = c.fetchall()

    c.execute("SELECT DATE(timestamp) as day, COUNT(*) FROM scans GROUP BY day ORDER BY day DESC LIMIT 7")
    daily = c.fetchall()

    conn.close()

    return render_template("dashboard.html",
                           total=total,
                           malicious=malicious,
                           suspicious=suspicious,
                           puw=puw,
                           safe=safe,
                           avg_score=avg_score,
                           top_threats=top_threats,
                           file_types=file_types,
                           daily=daily)

@app.route("/admin", methods=["GET", "POST"])
def admin():
    message = None
    if request.method == "POST":
        hash_val = request.form.get("hash", "").strip()
        name = request.form.get("name", "").strip()
        category = request.form.get("category", "").strip()
        severity = request.form.get("severity", 50)

        if hash_val:
            try:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute("INSERT OR REPLACE INTO malware (file_hash, malware_name, category, severity) VALUES (?, ?, ?, ?)",
                          (hash_val, name, category, int(severity)))
                conn.commit()
                conn.close()
                message = ("success", f"Signature '{name}' added successfully.")
            except Exception as e:
                message = ("error", f"Error: {e}")
        else:
            message = ("error", "Hash is required.")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM malware ORDER BY id DESC")
    signatures = c.fetchall()
    conn.close()
    return render_template("admin.html", message=message, signatures=signatures)

@app.route("/admin/delete/<int:sig_id>", methods=["POST"])
def delete_signature(sig_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM malware WHERE id=?", (sig_id,))
    conn.commit()
    conn.close()
    return redirect("/admin")

@app.route("/api/scan_status")
def api_scan_status():
    """Simple JSON endpoint for stats."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*), MAX(threat_score) FROM scans")
    row = c.fetchone()
    conn.close()
    return jsonify({"total_scans": row[0], "max_score_seen": row[1]})

if __name__ == "__main__":
    app.run(debug=True)
