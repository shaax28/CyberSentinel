import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    send_file,
    session
)

import sqlite3
import os
from dotenv import load_dotenv
from werkzeug.security import check_password_hash

from scanner.nmap_scanner import scan_target
from scanner.vulnerability import analyze_results
from reports.report_generator import generate_report


# Load environment variables
load_dotenv()


app = Flask(__name__)

# Secret key loaded from .env
app.secret_key = os.getenv("SECRET_KEY")

DB_NAME = "cybersentinel.db"


def get_results():

    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row

    results = conn.execute("""
        SELECT *
        FROM scan_results
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    return results


def calculate_risk(findings):

    if not findings:
        return "LOW"

    severities = [
        finding["severity"]
        for finding in findings
    ]

    if "CRITICAL" in severities:
        return "CRITICAL"

    if "HIGH" in severities:
        return "HIGH"

    if "MEDIUM" in severities:
        return "MEDIUM"

    return "LOW"


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        conn = sqlite3.connect(DB_NAME)

        user = conn.execute("""
            SELECT username, password
            FROM users
            WHERE username = ?
        """, (username,)).fetchone()

        conn.close()

        if user and check_password_hash(
            user[1],
            password
        ):

            session["logged_in"] = True
            session["username"] = username

            return redirect(
                url_for("dashboard")
            )

        return render_template(
            "login.html",
            error="Invalid username or password"
        )

    return render_template("login.html")


@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


@app.route("/")
def dashboard():

    if not session.get("logged_in"):
        return redirect(
            url_for("login")
        )

    results = get_results()

    results_dict = [
        dict(row)
        for row in results
    ]

    findings = analyze_results(
        results_dict
    )

    risk = calculate_risk(
        findings
    )

    return render_template(
        "dashboard.html",
        results=results_dict,
        findings=findings,
        risk=risk
    )


@app.route("/scan", methods=["POST"])
def start_scan():

    if not session.get("logged_in"):
        return redirect(
            url_for("login")
        )

    target = request.form.get(
        "target",
        ""
    ).strip()

    if target:
        scan_target(target)

    return redirect(
        url_for("dashboard")
    )


@app.route("/generate-report")
def generate_security_report():

    if not session.get("logged_in"):
        return redirect(
            url_for("login")
        )

    results = get_results()

    results_dict = [
        dict(row)
        for row in results
    ]

    findings = analyze_results(
        results_dict
    )

    risk = calculate_risk(
        findings
    )

    project_folder = os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )

    report_path = os.path.join(
        project_folder,
        "reports",
        "security_report.pdf"
    )

    os.makedirs(
        os.path.dirname(report_path),
        exist_ok=True
    )

    generate_report(
        results_dict,
        findings,
        risk,
        report_path
    )

    return send_file(
        report_path,
        as_attachment=True,
        download_name="CyberSentinel_Security_Report.pdf"
    )

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )