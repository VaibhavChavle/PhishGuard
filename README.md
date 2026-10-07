# PhishGuard

PhishGuard is a Flask-based web application that analyzes URLs and identifies common indicators associated with phishing and suspicious links.

## Overview

Phishing attacks often use deceptive URLs to trick users into revealing sensitive information.

PhishGuard performs rule-based URL analysis and assigns a risk score based on suspicious characteristics such as:

- Missing HTTPS
- IP addresses used instead of domain names
- Suspicious keywords
- Excessive subdomains
- `@` symbols
- Unusually long URLs
- Hyphens in domains
- URL-encoded characters

The application provides a simple security verdict along with the reasons behind the score.

## Features

- URL risk analysis
- Rule-based phishing detection
- Risk score from 0–100
- Detection reasons
- Simple web interface
- Flask backend
- Responsive interface
- No external database required

## How It Works

The application analyzes the structure of a submitted URL.

Each suspicious characteristic contributes points to the overall risk score.

### Current Risk Levels

| Score | Verdict |
|------:|---------|
| 0–29 | SAFE |
| 30–59 | SUSPICIOUS |
| 60–100 | PHISHING |

The score is capped at 100.

## Technologies Used

- Python
- Flask
- HTML
- CSS
- Git
- GitHub

## Project Structure

```text
PhishGuard/
│
├── detector/
│   ├── __init__.py
│   └── url_analyzer.py
│
├── static/
│
├── templates/
│   └── index.html
│
├── tests/
│
├── app.py
├── requirements.txt
├── .gitignore
└── README.md
