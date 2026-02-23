from pathlib import Path

import joblib
import pandas as pd
import shap

BASE = Path(__file__).resolve().parents[1]
DATASET = BASE / "data" / "phishing_dataset.csv"
MODEL_PATH = BASE / "models" / "phishing_model.joblib"
SHAP_PATH = BASE / "models" / "shap_summary.png"


def run() -> None:
    df = pd.read_csv(DATASET)
    x = df.drop(columns=["label"])
    model = joblib.load(MODEL_PATH)
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(x.iloc[:200])
    shap.summary_plot(shap_values, x.iloc[:200], show=False)
    import matplotlib.pyplot as plt

    plt.tight_layout()
    plt.savefig(SHAP_PATH)
    print(f"SHAP summary saved to {SHAP_PATH}")


if __name__ == "__main__":
    run()
