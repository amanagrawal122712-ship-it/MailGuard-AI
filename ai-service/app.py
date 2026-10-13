
import re
import ipaddress
from urllib.parse import urlparse
from html import unescape
from typing import Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


app = FastAPI(
    title="MailGuard AI",
    description="Rule-based phishing and suspicious email analyzer",
    version="3.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class EmailInput(BaseModel):
    sender: str = ""
    subject: str = ""
    body: str = ""
    from_: Optional[str] = Field(default=None, alias="from")

    model_config = {"populate_by_name": True}


URGENT_PATTERNS = [
    r"\burgent\b",
    r"\bimmediately\b",
    r"\bact now\b",
    r"\bwithin\s+24\s+hours\b",
    r"\bfinal warning\b",
    r"\baction required\b",
    r"\bverify your account\b",
    r"\baccount.{0,30}suspend(?:ed|ed)?\b",
    r"\bpermanently disabled\b",
    r"\byour account will be closed\b",
    r"\bunauthorized login\b",
    r"\bunusual sign[- ]in\b",
]

CREDENTIAL_PATTERNS = [
    r"\benter your password\b",
    r"\bprovide your password\b",
    r"\bconfirm your password\b",
    r"\bshare your password\b",
    r"\bverify your password\b",
    r"\benter your otp\b",
    r"\bshare your otp\b",
    r"\bverification code\b",
    r"\bcredit card details\b",
    r"\bbanking credentials\b",
    r"\blogin credentials\b",
    r"\breset your password\b",
    r"\bconfirm your identity\b",
    r"\bsecurity code\b",
]

PAYMENT_PATTERNS = [
    r"\bwire transfer\b",
    r"\bgift card\b",
    r"\bclaim your prize\b",
    r"\byou have won\b",
    r"\bpayment overdue\b",
    r"\bpay immediately\b",
    r"\brefund pending\b",
    r"\bupdate your payment\b",
    r"\bclaim your reward\b",
    r"\bprize money\b",
    r"\bprocessing fee\b",
]

SENSITIVE_REQUEST_PATTERNS = [
    r"\b(send|submit|upload|share)\b.{0,60}"
    r"\b(password|otp|bank details|card details|"
    r"security code|recovery code)\b",
    r"\b(password|otp|bank details|card details)\b.{0,60}"
    r"\b(send|submit|upload|share)\b",
]

SUSPICIOUS_PATHS = (
    "/login",
    "/verify",
    "/signin",
    "/account",
    "/password",
    "/secure",
    "/update",
    "/auth",
    "/credential",
)

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
}

OFFICIAL_BRANDS = {
    "google": {"google.com"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com"},
    "apple": {"apple.com"},
    "amazon": {"amazon.com"},
    "paypal": {"paypal.com"},
    "linkedin": {"linkedin.com"},
}


def clean_text(value: str) -> str:
    """Convert common HTML email content to readable text."""
    value = unescape(value or "")
    value = re.sub(
        r"<(script|style)\b[^>]*>[\s\S]*?</\1>",
        " ",
        value,
        flags=re.IGNORECASE,
    )
    value = re.sub(r"<!--[\s\S]*?-->", " ", value)
    value = re.sub(r"<br\s*/?>|</p>|</div>|</li>", "\n",
                    value, flags=re.IGNORECASE)
    value = re.sub(r"<[^>]+>", " ", value)
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def find_urls(text: str) -> list[str]:
    pattern = r"""(?i)\b(?:https?://|www\.)[^\s<>"']+"""
    urls = re.findall(pattern, text)
    return [url.rstrip(".,;:!?)\]}") for url in urls]


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def email_domain(sender: str) -> str:
    match = re.search(
        r"@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        sender,
    )
    return match.group(1).lower().rstrip(".") if match else ""


def sender_claims_brand(sender: str, brand: str) -> bool:
    # Check the local part and display name, not just the domain.
    local = sender.lower().split("@")[0]
    return bool(re.search(rf"\b{re.escape(brand)}\b", local))


def analyze_email(email: EmailInput) -> dict:
    sender = (email.sender or email.from_ or "").strip()
    subject = clean_text(email.subject or "")
    body = clean_text(email.body or "")

    text = f"{subject}\n{body}".lower()
    score = 0
    reasons = []
    signals = set()

    def add_signal(key: str, points: int, reason: str):
        nonlocal score
        if key not in signals:
            signals.add(key)
            score += points
            reasons.append(reason)

    # 1. Urgency, threats and account warnings
    if any(re.search(p, text, re.I) for p in URGENT_PATTERNS):
        add_signal("urgency", 15, "Urgent or threatening language detected")

    # 2. Password, OTP and credential requests
    if any(re.search(p, text, re.I) for p in CREDENTIAL_PATTERNS):
        add_signal("credentials", 25, "Possible credential or account-verification request")

    # 3. Payment and prize scams
    if any(re.search(p, text, re.I) for p in PAYMENT_PATTERNS):
        add_signal("payment", 20, "Payment, prize or financial scam indicators")

    if any(re.search(p, text, re.I) for p in SENSITIVE_REQUEST_PATTERNS):
        add_signal("sensitive_data", 20, "Request for sensitive personal or financial information")

    # 4. Job and work-from-home scam indicators
    job_terms = r"\b(job offer|work from home|remote job|data entry job|joining date|job vacancy|hiring|trainee|recruitment|earn up to|daily income)\b"
    fee_terms = r"\b(registration fee|processing fee|security deposit|training fee|pay to apply|payment required|refundable fee)\b"
    unrealistic_terms = r"\b(guaranteed income|no experience required|easy money|instant income|earn \d+.{0,20}(?:daily|per day|a day))\b"

    job_related = bool(re.search(job_terms, text, re.I))

    if job_related and re.search(fee_terms, text, re.I):
        add_signal("job_fee", 35, "Job-related message requests a fee or deposit")

    if job_related and re.search(unrealistic_terms, text, re.I):
        add_signal("job_income", 15, "Job message makes potentially unrealistic income claims")

    if re.search(r"\b(send money|pay now|deposit now|whatsapp me|telegram me)\b", text, re.I) and job_related:
        add_signal("job_contact", 15, "Job message combines payment or off-platform contact pressure")

    # 5. Suspicious links
    for raw_url in find_urls(f"{subject}\n{body}"):
        candidate = "http://" + raw_url if raw_url.lower().startswith("www.") else raw_url

        try:
            parsed = urlparse(candidate)
            host = (parsed.hostname or "").lower().rstrip(".")

            if not host:
                continue

            if parsed.scheme.lower() == "http":
                add_signal("http_url", 10, "Link uses HTTP rather than HTTPS")

            if is_ip_address(host):
                add_signal("ip_url", 25, "Link points directly to an IP address")

            if "xn--" in host:
                add_signal("punycode", 15, "Link contains a potentially deceptive encoded domain")

            if host in SHORTENERS:
                add_signal("shortener", 10, "Link uses a URL shortener")

            if any(path in parsed.path.lower() for path in SUSPICIOUS_PATHS):
                add_signal("login_path", 10, "Link contains a login or account-verification path")

            if host.count(".") >= 4:
                add_signal("complex_host", 10, "Link contains an unusually complex hostname")

        except (ValueError, UnicodeError):
            add_signal("malformed_url", 10, "A potentially malformed URL was detected")

    # 6. Brand impersonation
    domain = email_domain(sender)

    for brand, official_domains in OFFICIAL_BRANDS.items():
        claims_brand = sender_claims_brand(sender, brand)
        domain_matches = any(
            domain == official or domain.endswith("." + official)
            for official in official_domains
        )

        if claims_brand and domain and not domain_matches:
            add_signal(
                "sender_mismatch",
                25,
                f"Sender mentions {brand} but uses a different email domain",
            )
            break

    # 7. Combined phishing signals
    if "credentials" in signals and (
        "urgency" in signals or "http_url" in signals or "ip_url" in signals
    ):
        add_signal(
            "combined_phishing",
            15,
            "Credential request is combined with urgency or a risky link",
        )

    score = min(100, max(0, score))

    if score >= 70:
        verdict = "high_risk"
    elif score >= 40:
        verdict = "suspicious"
    elif score >= 20:
        verdict = "medium_risk"
    else:
        verdict = "low_risk"

    if not reasons:
        reasons.append(
            "No configured phishing indicators were detected; "
            "this does not guarantee the email is safe."
        )

    return {
        "risk_score": score,
        "verdict": verdict,
        "reasons": reasons,
        "model_type": "heuristic_v4",
        "warning": (
            "Rule-based preliminary analysis, not a trained ML model. "
            "A low score does not prove an email is genuine."
        ),
    }

@app.get("/")
def root():
    return {
        "app": "MailGuard AI",
        "status": "running",
        "analyze_endpoint": "/analyze",
        "docs": "/docs",
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "MailGuard AI Python analyzer",
        "model_type": "heuristic_v3",
    }


@app.post("/analyze")
def analyze(email: EmailInput):
    return analyze_email(email)
