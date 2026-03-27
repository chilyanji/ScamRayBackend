from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import re, hashlib
from datetime import datetime

app = FastAPI(title="PhishGuard API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

# ── Request Models ──────────────────────────────────────────
class UrlRequest(BaseModel):
    url: str
    context: Optional[str] = None

class TextRequest(BaseModel):
    text: str
    channel: str = "sms"

# ── Response Models ─────────────────────────────────────────
class ThreatReason(BaseModel):
    code: str
    description: str
    severity: str

class AnalysisResult(BaseModel):
    verdict: str
    confidence: float
    risk_score: int
    reasons: List[ThreatReason]
    recommended_action: str
    analysis_id: str
    timestamp: str

# ── Known Brands for Typosquatting Detection ────────────────
BRANDS = ["paypal","amazon","google","microsoft","apple","facebook",
          "netflix","instagram","twitter","linkedin","chase","citibank",
          "bankofamerica","wellsfargo","fedex","ups","usps","dropbox"]

# ── Suspicious TLDs ─────────────────────────────────────────
BAD_TLDS = [".xyz",".top",".club",".work",".click",".loan",
            ".tk",".ml",".cf",".ga",".gq",".pw"]

# ── Urgency/Phishing Patterns ───────────────────────────────
URGENCY_PATTERNS = [
    r'\b(urgent|immediately|act now|expires|suspended|limited time)\b',
    r'\b(verify your|confirm your|update your|validate your)\b',
    r'\b(won|winner|prize|reward|congratulation)\b',
    r'\b(unusual activity|suspicious login|unauthorized access)\b',
    r'\b(social security|ssn|tax refund|irs)\b',
    r'\b(click here|click below|click the link)\b',
]

CRED_PATTERNS = [
    r'\b(enter your|provide your|submit your)\s+(password|pin|otp|ssn|username)\b',
    r'\b(credit card|card number|cvv|expiry date)\b',
    r'\b(bank account|routing number)\b',
]

# ── Helper: Levenshtein distance (typosquatting) ────────────
def lev(a, b):
    if not a: return len(b)
    if not b: return len(a)
    prev = list(range(len(b)+1))
    for i, ca in enumerate(a):
        curr = [i+1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j]+(ca!=cb), curr[j]+1, prev[j+1]+1))
        prev = curr
    return prev[len(b)]

def extract_domain(url):
    url = re.sub(r'^https?://', '', url.lower()).replace('www.','')
    return url.split('/')[0].split('?')[0]

def check_typosquatting(domain):
    base = re.sub(r'\.[a-z]{2,}$', '', domain)
    base = base.replace('0','o').replace('1','l').replace('@','a')
    for brand in BRANDS:
        d = lev(base, brand)
        if 0 < d <= 2:
            return brand
    return None

# ── URL Analysis ─────────────────────────────────────────────
def analyze_url(url: str):
    reasons, score = [], 0
    domain = extract_domain(url)

    if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        score += 35
        reasons.append(ThreatReason(code="IP_IN_URL",
            description="URL uses a raw IP address instead of a domain — strong phishing indicator",
            severity="high"))

    brand = check_typosquatting(domain)
    if brand:
        score += 45
        reasons.append(ThreatReason(code="TYPOSQUATTING",
            description=f"Domain '{domain}' closely mimics the legitimate brand '{brand}.com'",
            severity="high"))

    for tld in BAD_TLDS:
        if domain.endswith(tld):
            score += 15
            reasons.append(ThreatReason(code="SUSPICIOUS_TLD",
                description=f"TLD '{tld}' is heavily associated with phishing campaigns",
                severity="medium"))
            break

    subs = len(domain.split('.')) - 2
    if subs > 2:
        score += 10 * (subs - 2)
        reasons.append(ThreatReason(code="SUBDOMAIN_ABUSE",
            description=f"{subs} subdomain levels used to obscure the real destination",
            severity="medium"))

    if not url.startswith('https://'):
        score += 10
        reasons.append(ThreatReason(code="NO_HTTPS",
            description="URL does not use HTTPS — connection is unencrypted",
            severity="medium"))

    if len(url) > 200:
        score += 10
        reasons.append(ThreatReason(code="LONG_URL",
            description=f"Unusually long URL ({len(url)} chars) used to hide malicious parameters",
            severity="low"))

    return min(score, 100), reasons

# ── Text Analysis ─────────────────────────────────────────────
def analyze_text(text: str):
    reasons, score = [], 0
    low = text.lower()

    urgency_hits = sum(1 for p in URGENCY_PATTERNS if re.search(p, low, re.IGNORECASE))
    if urgency_hits:
        score += min(urgency_hits * 14, 42)
        reasons.append(ThreatReason(code="URGENCY_LANGUAGE",
            description="High-pressure language detected — a hallmark of social engineering attacks",
            severity="high" if urgency_hits >= 2 else "medium"))

    if any(re.search(p, low, re.IGNORECASE) for p in CRED_PATTERNS):
        score += 40
        reasons.append(ThreatReason(code="CREDENTIAL_HARVESTING",
            description="Message attempts to collect sensitive credentials or financial information",
            severity="high"))

    urls = re.findall(r'https?://[^\s]+|www\.[^\s]+', text)
    for url in urls[:3]:
        url_score, url_reasons = analyze_url(url)
        if url_score > 30:
            score += min(url_score // 2, 30)
            domain = extract_domain(url)
            reasons.append(ThreatReason(code="MALICIOUS_URL",
                description=f"Suspicious URL detected: {domain}",
                severity="high" if url_score > 60 else "medium"))

    short_urls = ['bit.ly','tinyurl','t.co','goo.gl','ow.ly']
    if any(s in low for s in short_urls):
        score += 18
        reasons.append(ThreatReason(code="SHORTENED_URL",
            description="Shortened URL hides the true destination — frequently used in phishing",
            severity="medium"))

    return min(score, 100), reasons

# ── Build final response ─────────────────────────────────────
def build_response(score: int, reasons: list) -> AnalysisResult:
    if score >= 60:
        verdict, action = "malicious", "block_and_quarantine"
    elif score >= 25:
        verdict, action = "suspicious", "warn_user"
    else:
        verdict, action = "safe", "allow"

    confidence = round(min(0.5 + abs(score - 50) / 100, 0.98), 2)
    aid = hashlib.md5(datetime.now().isoformat().encode()).hexdigest()[:10]

    return AnalysisResult(
        verdict=verdict, confidence=confidence, risk_score=score,
        reasons=reasons, recommended_action=action,
        analysis_id=aid, timestamp=datetime.now().isoformat()
    )

# ── API Endpoints ─────────────────────────────────────────────

@app.get("/")
def root():
    return {"service": "PhishGuard", "status": "running", "version": "1.0.0"}

@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.post("/analyze/url", response_model=AnalysisResult)
def api_analyze_url(req: UrlRequest):
    score, reasons = analyze_url(req.url)
    return build_response(score, reasons)

@app.post("/analyze/text", response_model=AnalysisResult)
def api_analyze_text(req: TextRequest):
    score, reasons = analyze_text(req.text)
    return build_response(score, reasons)

if __name__ == "__main__":
    import uvicorn
    print("\n🛡️  ScamRay Backend Starting...")
    print("📡  Server: http://localhost:8000")
    print("📱  Emulator: http://10.0.2.2:8000")
    print("📄  API Docs: http://localhost:8000/docs\n")
    uvicorn.run(app, host="0.0.0.0", port=8000)
