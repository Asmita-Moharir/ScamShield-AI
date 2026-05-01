import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
import joblib

data = {
    "text": [
        "Congratulations you won money click now",
        "Pay fee to receive reward",
        "Verify your bank account urgently",
        "Meeting at 5 pm tomorrow",
        "Please submit assignment today",
        "Lunch at 1 pm"
    ],
    "label": [1,1,1,0,0,0]
}

df = pd.DataFrame(data)

X_train, X_test, y_train, y_test = train_test_split(
    df["text"], df["label"], test_size=0.2, random_state=42
)

model = Pipeline([
    ("tfidf", TfidfVectorizer()),
    ("clf", LogisticRegression())
])

model.fit(X_train, y_train)

joblib.dump(model, "scam_model.pkl")

print("Model trained.")