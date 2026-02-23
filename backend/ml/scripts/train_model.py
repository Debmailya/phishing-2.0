from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import ConfusionMatrixDisplay, classification_report
from sklearn.model_selection import train_test_split

BASE = Path(__file__).resolve().parents[1]
DATASET = BASE / "data" / "phishing_dataset.csv"
MODEL_PATH = BASE / "models" / "phishing_model.joblib"
CM_PATH = BASE / "models" / "confusion_matrix.png"
FEATURES_PATH = BASE / "models" / "feature_importance.csv"


def run() -> None:
    df = pd.read_csv(DATASET)
    y = df.pop("label")
    x_train, x_test, y_train, y_test = train_test_split(df, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=200, random_state=42, class_weight="balanced")
    model.fit(x_train, y_train)
    preds = model.predict(x_test)

    print(classification_report(y_test, preds))
    disp = ConfusionMatrixDisplay.from_predictions(y_test, preds)
    disp.figure_.savefig(CM_PATH)

    importances = pd.DataFrame({"feature": df.columns, "importance": model.feature_importances_})
    importances.sort_values("importance", ascending=False).to_csv(FEATURES_PATH, index=False)
    joblib.dump(model, MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")


if __name__ == "__main__":
    run()
