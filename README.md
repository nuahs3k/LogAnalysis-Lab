# Log Analysis Lab 🛡️

## 📌 Overview
This project simulates a **Security Operations Center (SOC) task**: analyzing system logs to detect suspicious activity such as **failed logins** and **potential brute-force attempts**.  

It is designed as a **hands-on Security+ style project** that demonstrates how log analysis can be automated with Python.

---

## 🗂️ Project Structure
LogAnalysis/
│
├─ scripts/
│ └─ log_analysis.py # Python script to parse logs
│
├─ sample_logs/
│ └─ syslog_sample.log # Example system log file
│
├─ outputs/
│ └─ failed_logins.csv # Generated report of suspicious logins
│
├─ screenshots/
│ └─ (Screenshots of analysis & outputs go here)


---

## ▶️ How to Run

1. **Clone the repository**  
   ```bash
   git clone https://github.com/<your-username>/LogAnalysis.git
   cd LogAnalysis/scripts
Make sure Python 3 is installed

bash
Copy code
python --version
Run the script
From inside the scripts/ directory:

bash
Copy code
python log_analysis.py
Check the output
The script will:

Parse logs from ../sample_logs/syslog_sample.log

Create a CSV report at ../outputs/failed_logins.csv

Open the CSV with Excel or a text editor to review suspicious login attempts.



---

## ⚙️ Tools & Technologies
- **Python 3** → Log parsing & CSV report generation  
- **Regex (re module)** → Extract login failure events from logs  
- **CSV module** → Export suspicious events into a structured report  
- **Windows PowerShell** → Running the script  
- **Git & GitHub** → Version control & project hosting  

---

## 🚀 How It Works
1. The Python script reads a log file (`syslog_sample.log`).  
2. It searches for failed login attempts.  
3. Extracted details include:
   - Timestamp  
   - Username (if available)  
   - Source IP address  
4. Results are exported into a CSV file (`outputs/failed_logins.csv`).  
5. Analyst reviews the report to determine possible brute-force or malicious activity.  

---

## 📸 Screenshots
Below are some screenshots captured during the lab:  

1. **Running the script in PowerShell**  
   ![Run Script](screenshots/run_script.png)

2. **Generated CSV output**  
   ![CSV Output](screenshots/csv_output.png)

3. **Log file snippet with failed logins**  
   ![Log Snippet](screenshots/log_snippet.png)

---

## 🎯 What I Learned
- How to analyze raw log files for suspicious authentication attempts.  
- How to automate log parsing with Python using regex.  
- How to export structured security reports for further SOC investigation.  
- The importance of monitoring failed login attempts for **early detection of brute-force attacks**.  

---

## 🔐 Relevance to Cybersecurity
- This project mirrors **real SOC analyst workflows**: reviewing system logs, identifying anomalies, and generating incident reports.  
- Demonstrates **log analysis skills** that apply to SIEM tools like **Splunk**, **ELK Stack**, or **AWS CloudWatch Logs**.  
- Strengthens knowledge relevant for **CompTIA Security+**, **SOC Analyst**, and **Cloud Security** roles.  

---

## 📈 Next Steps
- Expand the script to detect **successful logins after multiple failures**.  
- Add **GeoIP lookup** to map suspicious IP addresses to locations.  
- Integrate into a **cloud-based log monitoring pipeline** for real-time alerting.  

---
