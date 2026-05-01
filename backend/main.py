from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse
from PIL import Image
import pytesseract
import io
import re
import os

# ==================================================
# APP
# ==================================================
app = FastAPI(title="ScamShield AI Backend")

# ==================================================
# FINAL SIMPLE CORS FIX
# ==================================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================================================
# OCR PATH (WINDOWS LOCAL ONLY)
# ==================================================
if os.name == "nt":
    pytesseract.pytesseract.tesseract_cmd = (
        r"C:\Program Files\Tesseract-OCR\tesseract.exe"
    )

# ==================================================
# MODELS
# ==================================================
class TextInput(BaseModel):
    text: str


class URLInput(BaseModel):
    url: str


# ==================================================
# HELPERS
# ==================================================
def risk_level(score):
    if score >= 70:
        return "High Risk"
    elif score >= 40:
        return "Medium Risk"
    return "Low Risk"


# ==================================================
# HOME
# ==================================================
@app.get("/")
def home():
    return {"message": "ScamShield AI Backend Running"}


# ==================================================
# TEXT SCAM DETECTOR
# ==================================================
@app.post("/analyze")
def analyze(data: TextInput):
    text = data.text.lower()

    score = 0
    reasons = []

    suspicious_words = [
        "urgent",
        "winner",
        "free",
        "money",
        "otp",
        "click",
        "verify",
        "claim",
        "gift",
        "lottery",
        "bank",
        "password",
        "limited time",
        "account blocked",
    ]

    for word in suspicious_words:
        if word in text:
            score += 10
            reasons.append(f"Contains suspicious phrase: {word}")

    if re.search(r"http[s]?://", text):
        score += 20
        reasons.append("Contains suspicious link")

    if len(text.strip()) < 8:
        score += 10
        reasons.append("Very short suspicious message")

    score = min(score, 100)

    return {
        "score": score,
        "risk_level": risk_level(score),
        "reasons": reasons if reasons else ["No major scam indicators found"],
    }


# ==================================================
# URL PHISHING DETECTOR
# ==================================================
@app.post("/scan-url")
def scan_url(data: URLInput):
    url = data.url.lower()

    score = 0
    reasons = []

    bad_tlds = [".xyz", ".top", ".click", ".ru", ".loan", ".tk"]
    fake_words = [
        "login",
        "verify",
        "secure",
        "update",
        "gift",
        "bank",
        "paytm",
        "amazon",
        "gpay",
        "wallet",
    ]

    parsed = urlparse(url)
    domain = parsed.netloc

    if not domain:
        return {
            "score": 100,
            "risk_level": "High Risk",
            "reasons": ["Invalid URL format"],
        }

    for tld in bad_tlds:
        if domain.endswith(tld):
            score += 35
            reasons.append(f"Suspicious domain ending: {tld}")

    for word in fake_words:
        if word in domain:
            score += 10
            reasons.append(f"Contains phishing keyword: {word}")

    if "-" in domain:
        score += 10
        reasons.append("Hyphenated domain")

    if len(domain) > 25:
        score += 10
        reasons.append("Very long domain")

    score = min(score, 100)

    return {
        "score": score,
        "risk_level": risk_level(score),
        "reasons": reasons if reasons else ["Looks relatively safe"],
    }


# ==================================================
# JOB SCAM DETECTOR
# ==================================================
@app.post("/scan-job")
def scan_job(data: TextInput):
    text = data.text.lower()

    score = 0
    reasons = []

    phrases = [
        "registration fee",
        "pay fee",
        "security deposit",
        "immediate joining",
        "whatsapp only",
        "no interview",
        "guaranteed job",
        "earn daily",
        "work from home no skills",
    ]

    for item in phrases:
        if item in text:
            score += 15
            reasons.append(f"Contains suspicious phrase: {item}")

    if "salary" in text and "no experience" in text:
        score += 20
        reasons.append("Unrealistic salary + no experience")

    score = min(score, 100)

    return {
        "score": score,
        "risk_level": risk_level(score),
        "reasons": reasons if reasons else ["No major fake job indicators found"],
    }


# ==================================================
# OCR IMAGE SCAN
# ==================================================
@app.post("/scan-image")
async def scan_image(file: UploadFile = File(...)):
    try:
        image_bytes = await file.read()
        image = Image.open(io.BytesIO(image_bytes))

        extracted_text = pytesseract.image_to_string(image)
        text = extracted_text.lower()

        score = 0
        reasons = []

        words = [
            "urgent",
            "winner",
            "otp",
            "verify",
            "claim",
            "money",
            "gift",
        ]

        for word in words:
            if word in text:
                score += 12
                reasons.append(f"OCR found suspicious word: {word}")

        score = min(score, 100)

        return {
            "score": score,
            "risk_level": risk_level(score),
            "reasons": reasons if reasons else ["No scam indicators found"],
            "extracted_text": extracted_text,
        }

    except Exception as e:
        return {
            "score": 0,
            "risk_level": "Unavailable",
            "reasons": [f"OCR unavailable: {str(e)}"],
            "extracted_text": "",
        }