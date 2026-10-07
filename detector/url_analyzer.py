from urllib.parse import urlparse
import ipaddress


def analyze_url(url):
    score = 0
    reasons = []

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # 1. URL length
    if len(url) > 75:
        score += 10
        reasons.append("Unusually long URL")

    # 2. HTTPS
    if parsed.scheme != "https":
        score += 15
        reasons.append("URL does not use HTTPS")

    # 3. IP address instead of domain
    try:
        ipaddress.ip_address(hostname)
        score += 25
        reasons.append("IP address used instead of a domain name")
    except ValueError:
        pass

    # 4. @ symbol
    if "@" in url:
        score += 20
        reasons.append("@ symbol found in URL")

    # 5. Suspicious keywords
    suspicious_words = [
        "login",
        "verify",
        "verification",
        "account",
        "secure",
        "update",
        "password",
        "signin",
        "bank"
    ]

    found_words = [
        word for word in suspicious_words
        if word in url.lower()
    ]

    if found_words:
        score += 10
        reasons.append(
            "Suspicious keywords: " + ", ".join(found_words)
        )

    # 6. Excessive subdomains
    if hostname.count(".") >= 3:
        score += 10
        reasons.append("Excessive number of subdomains")

    # 7. Hyphen in domain
    if "-" in hostname:
        score += 5
        reasons.append("Hyphen detected in domain")

    # 8. URL encoding
    if "%" in url:
        score += 5
        reasons.append("URL contains encoded characters")

    # Maximum score = 100
    score = min(score, 100)

    # Verdict
    if score >= 60:
        verdict = "PHISHING"
    elif score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return {
        "url": url,
        "score": score,
        "verdict": verdict,
        "reasons": reasons
    }