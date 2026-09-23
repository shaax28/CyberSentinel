\# 🛡️ CyberSentinel



\### Advanced Network Security Monitoring \& Vulnerability Assessment Platform



CyberSentinel is a Python-based cybersecurity platform designed for

authorized network security testing, monitoring, vulnerability assessment,

scan history management, and security report generation.



\---



\## 🚀 Features



\- 🔐 Secure user authentication

\- 🔑 Password hashing using Werkzeug

\- 🔍 Nmap-based network scanning

\- 🧪 Service and version detection

\- ⚠️ Potentially risky service detection

\- 📊 Security monitoring dashboard

\- 🕒 Scan history

\- 🗄️ SQLite database

\- 📄 Automated PDF security reports

\- 🚪 Login and logout session management

\- 🖥️ Flask web interface



\---



\## 🛠️ Technologies Used



\- Python 3

\- Flask

\- Nmap

\- python-nmap

\- SQLite

\- ReportLab

\- Werkzeug

\- HTML

\- CSS



\---



\## 📁 Project Structure



```text

CyberSentinel/

│

├── app/

│   ├── app.py

│   └── templates/

│       ├── dashboard.html

│       └── login.html

│

├── scanner/

│   ├── \_\_init\_\_.py

│   ├── nmap\_scanner.py

│   └── vulnerability.py

│

├── reports/

│   └── report\_generator.py

│

├── database/

│   └── db.py

│

├── tests/

│

├── requirements.txt

├── .gitignore

└── README.md

