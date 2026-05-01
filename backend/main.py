from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import re
from urllib.parse import urlparse
import joblib
import pytesseract
from PIL import Image
import io
import pytesseract
import os

if os.name == "nt":
    pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

app = FastAPI()

# ---------------------------------------------------
# CORS
# ---------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "https://your-vercel-domain.vercel.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------
# LOAD MODEL
# ---------------------------------------------------
try:
    model = joblib.load("scam_model.pkl")
except:
    model = None


# ---------------------------------------------------
# REQUEST MODELS
# ---------------------------------------------------
class ScanRequest(BaseModel):
    text: str


class URLRequest(BaseModel):
    url: str


class JobRequest(BaseModel):
    text: str


# ---------------------------------------------------
# COMMON SUSPICIOUS WORDS
# ---------------------------------------------------
highlight_words = [
    "urgent",
    "click now",
    "winner",
    "won",
    "otp",
    "pay fee",
    "free money",
    "verify account",
    "limited time",
    "congratulations",
    "bank details",
    "registration fee",
    "telegram",
    "whatsapp only",
    "no interview",
    "immediate joining",
]


# ---------------------------------------------------
# HOME
# ---------------------------------------------------
@app.get("/")
def home():
    return {"message": "ScamShield AI Backend Running"}


# ---------------------------------------------------
# COMMON TEXT DETECTOR
# ---------------------------------------------------
def detect_text_scam(text):
    text_lower = text.lower()

    score = 0
    reasons = []
    detected_keywords = []

    for word in highlight_words:
        if word in text_lower:
            score += 12
            reasons.append(f"Detected suspicious phrase: '{word}'")
            detected_keywords.append(word)

    urls = re.findall(r'https?://\S+|www\.\S+', text_lower)
    if urls:
        score += 20
        reasons.append("Contains suspicious link")

    if "₹" in text or "rs" in text_lower:
        score += 10
        reasons.append("Money-related bait detected")
        detected_keywords.append("₹")

    if model:
        prediction = model.predict([text])[0]
        if prediction == 1:
            score += 30
            reasons.append("ML model predicts scam pattern")

    if score > 100:
        score = 100

    level = "Low Risk"
    if score >= 70:
        level = "High Risk"
    elif score >= 40:
        level = "Medium Risk"

    if not reasons:
        reasons.append("No major scam signals found")

    return {
        "score": score,
        "risk_level": level,
        "reasons": reasons,
        "highlights": list(set(detected_keywords))
    }


# ---------------------------------------------------
# TEXT SCAN
# ---------------------------------------------------
@app.post("/analyze")
def analyze(req: ScanRequest):
    return detect_text_scam(req.text)


# ---------------------------------------------------
# URL SCAN
# ---------------------------------------------------
@app.post("/scan-url")
def scan_url(req: URLRequest):
    url = req.url.lower()

    score = 0
    reasons = []
    highlights = []

    suspicious_tlds = [".xyz", ".top", ".click", ".loan", ".ru"]
    fake_brands = ["paytm", "gpay", "google", "amazon", "flipkart", "bank"]

    parsed = urlparse(url)
    domain = parsed.netloc if parsed.netloc else url

    if domain.count("-") >= 2:
        score += 20
        reasons.append("Too many hyphens in domain")

    for tld in suspicious_tlds:
        if domain.endswith(tld):
            score += 25
            reasons.append(f"Suspicious domain ending: {tld}")
            highlights.append(tld)

    for brand in fake_brands:
        if brand in domain and brand not in [f"{brand}.com", f"www.{brand}.com"]:
            score += 30
            reasons.append(f"Possible brand impersonation: {brand}")
            highlights.append(brand)

    if any(char.isdigit() for char in domain):
        score += 10
        reasons.append("Contains numbers in domain")

    if len(domain) > 30:
        score += 15
        reasons.append("Unusually long domain")

    if score > 100:
        score = 100

    level = "Low Risk"
    if score >= 70:
        level = "High Risk"
    elif score >= 40:
        level = "Medium Risk"

    if not reasons:
        reasons.append("No major phishing signals found")

    return {
        "score": score,
        "risk_level": level,
        "reasons": reasons,
        "highlights": highlights
    }


# ---------------------------------------------------
# JOB SCAM SCAN
# ---------------------------------------------------
@app.post("/scan-job")
def scan_job(req: JobRequest):
    result = detect_text_scam(req.text)

    extra_words = [
        "work from home",
        "earn daily",
        "joining fee",
        "processing fee"
    ]

    text_lower = req.text.lower()

    for word in extra_words:
        if word in text_lower:
            result["score"] += 15
            result["reasons"].append(f"Job scam phrase: '{word}'")
            result["highlights"].append(word)

    if result["score"] > 100:
        result["score"] = 100

    if result["score"] >= 70:
        result["risk_level"] = "High Risk"
    elif result["score"] >= 40:
        result["risk_level"] = "Medium Risk"
    else:
        result["risk_level"] = "Low Risk"

    return result


# ---------------------------------------------------
# OCR IMAGE SCAN
# ---------------------------------------------------
@app.post("/scan-image")
async def scan_image(file: UploadFile = File(...)):
    contents = await file.read()

    image = Image.open(io.BytesIO(contents))

    extracted_text = pytesseract.image_to_string(image)

    result = detect_text_scam(extracted_text)

    result["extracted_text"] = extracted_text.strip()

    return result