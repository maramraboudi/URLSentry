from pathlib import Path

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    fbeta_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier


def get_metrics(model, X, y):
    """Calculate classification metrics."""

    predictions = model.predict(X)
    probabilities = model.predict_proba(X)[:, 1]

    return {
        "accuracy": accuracy_score(y, predictions),
        "precision": precision_score(
            y, predictions, zero_division=0
        ),
        "recall": recall_score(
            y, predictions, zero_division=0
        ),
        "f1_score": fbeta_score(
            y, predictions, beta=1, zero_division=0
        ),
        "f2_score": fbeta_score(
            y, predictions, beta=2, zero_division=0
        ),
        "roc_auc": roc_auc_score(y, probabilities),
        "pr_auc": average_precision_score(y, probabilities),
    }


def train_models():
    project_root = Path(__file__).resolve().parents[2]

    split_dir = project_root / "data" / "processed" / "splits"
    models_dir = project_root / "models"
    reports_dir = project_root / "reports"

    models_dir.mkdir(parents=True, exist_ok=True)

    train_path = split_dir / "train.csv"
    validation_path = split_dir / "validation.csv"

    if not train_path.exists() or not validation_path.exists():
        raise FileNotFoundError(
            "Training splits are missing. Run split_dataset.py first."
        )

    print("[INFO] Loading training and validation datasets...")

    train_df = pd.read_csv(train_path)
    validation_df = pd.read_csv(validation_path)

    excluded_columns = ["url", "is_phishing"]

    feature_columns = [
        column
        for column in train_df.columns
        if column not in excluded_columns
    ]

    X_train = train_df[feature_columns]
    y_train = train_df["is_phishing"]

    X_validation = validation_df[feature_columns]
    y_validation = validation_df["is_phishing"]

    if not y_train.nunique() == 2:
        raise ValueError("Training data must contain both classes.")

    if not y_validation.nunique() == 2:
        raise ValueError("Validation data must contain both classes.")

    print(f"[INFO] Training records: {len(X_train)}")
    print(f"[INFO] Validation records: {len(X_validation)}")
    print(f"[INFO] Features: {len(feature_columns)}")

    models = {
        "logistic_regression": Pipeline([
            ("scaler", StandardScaler()),
            (
                "classifier",
                LogisticRegression(
                    max_iter=1000,
                    class_weight="balanced",
                    random_state=42,
                ),
            ),
        ]),

        "decision_tree": DecisionTreeClassifier(
            max_depth=18,
            min_samples_leaf=5,
            class_weight="balanced",
            random_state=42,
        ),

        "random_forest": RandomForestClassifier(
            n_estimators=120,
            max_depth=20,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=42,
            n_jobs=2,
        ),
    }

    results = []

    print("\n========== MODEL TRAINING ==========")

    for name, model in models.items():
        print(f"\n[TRAINING] {name}")

        model.fit(X_train, y_train)

        metrics = get_metrics(
            model,
            X_validation,
            y_validation,
        )

        metrics["model"] = name

        results.append(metrics)

        model_path = models_dir / f"{name}.joblib"
        joblib.dump(model, model_path)

        print("[OK] Training completed.")
        print(f"Saved: {model_path}")

        for metric, value in metrics.items():
            if metric != "model":
                print(f"{metric}: {value:.4f}")

    results_df = pd.DataFrame(results)

    results_df = results_df[
        [
            "model",
            "accuracy",
            "precision",
            "recall",
            "f1_score",
            "f2_score",
            "roc_auc",
            "pr_auc",
        ]
    ]

    results_df = results_df.sort_values(
        by="f2_score",
        ascending=False,
    )

    results_path = reports_dir / "model_comparison.csv"
    results_df.to_csv(results_path, index=False)

    # Select using validation F2 score.
    # F2 gives more importance to recall.
    best_model_name = results_df.iloc[0]["model"]

    best_model = models[best_model_name]

    best_model_path = models_dir / "best_model.joblib"
    joblib.dump(best_model, best_model_path)

    print("\n========== MODEL COMPARISON ==========")
    print(results_df.to_string(index=False))

    print("\n========== SELECTED MODEL ==========")
    print(f"Best model: {best_model_name}")
    print("Selection criterion: Validation F2 score")
    print(f"Saved to: {best_model_path}")

    print("\n[OK] Model training completed.")


if __name__ == "__main__":
    train_models()
