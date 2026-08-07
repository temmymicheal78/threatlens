"""ThreatLens -- Unified Multi-Vector Threat Analysis Platform.

Flask entry point. Users submit any suspicious indicator (IP, URL, email
or file hash) and receive a security verdict backed by multiple threat
intelligence sources.

Author: Temiloluwa Michael Ogunrinde
"""

import os

from flask import Flask, render_template, request

import config
import database
from modules import ip_scanner as ip_module
from modules import url_scanner as url_module
from modules import email_analyzer as email_module
from modules import file_scanner as file_module
from threat_intel import whois_lookup

app = Flask(__name__)

# Cap uploads at 32 MB. Files are only hashed, never stored, but an
# unbounded upload would still tie up the request.
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024

# Create the scans table on startup if it does not exist yet.
database.init_db()


@app.errorhandler(413)
def file_too_large(_error):
    """Show the size limit on the scanner page instead of a bare 413."""
    return render_template(
        'file_scanner.html',
        active='file',
        result=None,
        error='That file is larger than the 32 MB limit. Paste its hash instead.',
        submitted=None,
    ), 413


# ------------------------------------------------------------- dashboard
@app.route('/')
def dashboard():
    """Overview page: scan counters and recent scan history."""
    return render_template(
        'dashboard.html',
        active='dashboard',
        stats=database.get_stats(),
        recent_scans=database.get_recent_scans(limit=10),
    )


# --------------------------------------------------------- scanner tabs
@app.route('/ip', methods=['GET', 'POST'])
def ip_scanner():
    """IP reputation scanner (AbuseIPDB, VirusTotal, geolocation).

    GET shows the empty form; POST runs the scan and shows the results.
    """
    result = None
    error = None
    submitted = None

    if request.method == 'POST':
        submitted = request.form.get('ip', '')
        result = ip_module.scan(submitted)
        if not result['ok']:
            error = result['error']
            result = None

    return render_template(
        'ip_scanner.html',
        active='ip',
        result=result,
        error=error,
        submitted=submitted,
        missing_keys=config.missing_keys(),
    )


@app.route('/url', methods=['GET', 'POST'])
def url_scanner():
    """URL and domain safety scanner (VirusTotal, WHOIS).

    GET shows the empty form; POST runs the scan and shows the results.
    """
    result = None
    error = None
    submitted = None

    if request.method == 'POST':
        submitted = request.form.get('url', '')
        result = url_module.scan(submitted)
        if not result['ok']:
            error = result['error']
            result = None

    return render_template(
        'url_scanner.html',
        active='url',
        result=result,
        error=error,
        submitted=submitted,
        whois_missing=not whois_lookup.WHOIS_AVAILABLE,
    )


@app.route('/email', methods=['GET', 'POST'])
def email_analyzer():
    """Phishing detection via email header analysis.

    GET shows the empty form; POST analyses the pasted email.
    """
    result = None
    error = None
    submitted = None

    if request.method == 'POST':
        submitted = request.form.get('raw_email', '')
        result = email_module.analyze(submitted)
        if not result['ok']:
            error = result['error']
            result = None

    return render_template(
        'email_analyzer.html',
        active='email',
        result=result,
        error=error,
        submitted=submitted,
    )


@app.route('/file', methods=['GET', 'POST'])
def file_scanner():
    """Malware detection via file hash lookup.

    Accepts either a pasted hash or an uploaded file, which is hashed
    locally so that the file itself is never transmitted.
    """
    result = None
    error = None
    submitted = None

    if request.method == 'POST':
        submitted = request.form.get('hash', '')
        uploaded = request.files.get('file')
        result = file_module.scan(raw_hash=submitted, uploaded_file=uploaded)
        if not result['ok']:
            error = result['error']
            result = None

    return render_template(
        'file_scanner.html',
        active='file',
        result=result,
        error=error,
        submitted=submitted,
    )


if __name__ == '__main__':
    # Debug mode exposes an interactive debugger that can execute arbitrary
    # code, so it stays off unless explicitly switched on for local work.
    # In production gunicorn imports `app` directly and never runs this.
    debug_mode = os.environ.get('FLASK_DEBUG', '1') == '1'
    app.run(debug=debug_mode)
