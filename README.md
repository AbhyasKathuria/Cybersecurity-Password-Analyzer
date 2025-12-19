# Cybersecurity-Password-Analyzer
# 🔐 Password Strength Analyzer with Custom Wordlist Generator

**Elevate Labs Cybersecurity Internship – Project #4**  
**Completed on: December 19, 2025**  
**Submitted by: [Your Full Name]**  

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Educational-green)]()

## 📌 Project Overview
This tool evaluates password strength using industry-standard methods and generates custom wordlists from personal information to demonstrate real-world password cracking risks **(for educational purposes only)**.

### Key Features
- **Password Analysis**:
  - Uses `zxcvbn` library (same as Dropbox) for realistic scoring (0–4)
  - Calculates Shannon entropy
  - Shows estimated offline crack time
  - Provides warnings and improvement suggestions
- **Custom Wordlist Generator**:
  - Accepts personal inputs (name, birth year, pet, city, etc.)
  - Applies transformations: leetspeak, capitalization, year/number appending, reversals, combinations
  - Optional inclusion of common English words (NLTK)
  - Exports to `.txt` file
- **User Interface**:
  - Command Line Interface (CLI)
  - Clean Tkinter Graphical User Interface (GUI)

## 🚀 Demo Screenshots

![GUI Main Window](gui_screenshot.png)
![Password Analysis Result](analysis_result.png)
![Wordlist Generation & Export](wordlist_output.png)

## 🛠️ Tools & Technologies Used
- Python 3.x
- zxcvbn – Realistic password strength estimation
- NLTK – Common English word corpus
- Tkinter – GUI framework
- argparse, itertools, datetime

## 📂 Project Structure
├── password_analyzer.py          # Main script
├── Password_Analyzer_Report.pdf  # Official internship report
├── gui_screenshot.png
├── analysis_result.png
├── wordlist_output.png
└── custom_wordlist_sample.txt    # Example output
text## ▶️ How to Run

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/Cybersecurity-Password-Analyzer.git
   cd Cybersecurity-Password-Analyzer

Install dependencies:Bashpip install zxcvbn nltk
Run the tool:
GUI Mode (recommended):Bashpython password_analyzer.py
CLI Examples:Bashpython password_analyzer.py --analyze "MyWeakPass123"
python password_analyzer.py --generate john 1998 tiger delhi --use_nltk


📄 Report
Full 2-page project report (as per Elevate Labs guidelines) is included:
Password_Analyzer_Report.pdf
🎯 Learning Outcomes

Deep understanding of password entropy and cracking techniques
Hands-on experience with ethical cybersecurity tool development
Improved ability to explain password security in interviews
Relates directly to interview topics like hashing, encryption, and common vulnerabilities

⚠️ Ethical Note
This tool is built solely for educational and awareness purposes.
It demonstrates why weak passwords are dangerous and promotes strong password practices.

Thank you, Elevate Labs, for this amazing learning opportunity! 🚀
#CyberSecurity #Python #EthicalHacking #InternshipProject
