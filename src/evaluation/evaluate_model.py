import json
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from sklearn.inspection import permutation_importance
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    fbeta_score,
    precision_score,
    precision_recall_curve,
    recall_score,
    roc_auc_score,
    roc_curve,
)


def calculate_metrics(y_true, predictions, probabilities):
    return {
        "accuracy": accuracy_score(y_true, predictions),
        "precision": precision_score(
            y_true, predictions, zero_division=0
        ),
        "recall": recall_score(
            y_true, predictions, zero_division=0
        ),
        "f1_score": fbeta_score(
            y_true, predictions, beta=1, zero_division=0
        ),
        "f2_score": fbeta_score(
            y_true, predictions, beta=2, zero_division=0
        ),
        "roc_auc": roc_auc_score(y_true, probabilities),
        "pr_auc": average_precision_score(y_true, probabilities),
    }


def evaluate_model():
    root = Path(__file__).resolve().parents[2]

    models_dir = root / "models"
    splits_dir = root / "data" / "processed" / "splits"
    reports_dir = root / "reports"
    figures_dir = reports_dir / "figures"

    reports_dir.mkdir(exist_ok=True)
    figures_dir.mkdir(parents=True, exist_ok=True)

    model_path = models_dir / "best_model.joblib"

    train_path = splits_dir / "train.csv"
    validation_path = splits_dir / "validation.csv"
    test_path = splits_dir / "test.csv"

    for path in [
        model_path,
        train_path,
        validation_path,
        test_path,
    ]:
        if not path.exists():
            raise FileNotFoundError(f"Required file missing: {path}")

    print("[INFO] Loading selected model and datasets...")

    model = joblib.load(model_path)

    train_df = pd.read_csv(train_path)
    validation_df = pd.read_csv(validation_path)
    test_df = pd.read_csv(test_path)

    excluded = ["url", "is_phishing"]

    feature_columns = [
        column for column in train_df.columns
        if column not in excluded
    ]

    X_validation = validation_df[feature_columns]
    y_validation = validation_df["is_phishing"]

    X_test = test_df[feature_columns]
    y_test = test_df["is_phishing"]

    # -------------------------------------------------
    # 1. Select the threshold using validation data only.
    # -------------------------------------------------

    validation_probabilities = model.predict_proba(
        X_validation
    )[:, 1]

    thresholds = np.arange(0.05, 0.96, 0.01)

    threshold_results = []

    for threshold in thresholds:
        predictions = (
            validation_probabilities >= threshold
        ).astype(int)

        threshold_results.append({
            "threshold": float(threshold),
            "f2_score": fbeta_score(
                y_validation,
                predictions,
                beta=2,
                zero_division=0,
            ),
            "precision": precision_score(
                y_validation,
                predictions,
                zero_division=0,
            ),
            "recall": recall_score(
                y_validation,
                predictions,
                zero_division=0,
            ),
        })

    threshold_df = pd.DataFrame(threshold_results)

    # Among thresholds with the same F2, prefer the higher threshold.
    best_threshold = threshold_df.sort_values(
        ["f2_score", "threshold"],
        ascending=[False, False],
    ).iloc[0]["threshold"]

    threshold_df.to_csv(
        reports_dir / "threshold_comparison.csv",
        index=False,
    )

    print(f"[INFO] Selected validation threshold: {best_threshold:.2f}")

    # -------------------------------------------------
    # 2. Final evaluation on untouched test data.
    # -------------------------------------------------

    test_probabilities = model.predict_proba(X_test)[:, 1]

    test_predictions = (
        test_probabilities >= best_threshold
    ).astype(int)

    metrics = calculate_metrics(
        y_test,
        test_predictions,
        test_probabilities,
    )

    metrics["threshold"] = float(best_threshold)

    metrics_df = pd.DataFrame(
        [metrics],
        index=["best_model"],
    )

    metrics_df.to_csv(
        reports_dir / "final_test_metrics.csv"
    )

    print("\n========== FINAL TEST RESULTS ==========")

    for name, value in metrics.items():
        print(f"{name}: {value:.4f}")

    print("\n========== CLASSIFICATION REPORT ==========")

    report = classification_report(
        y_test,
        test_predictions,
        target_names=["Legitimate", "Phishing"],
        zero_division=0,
    )

    print(report)

    (reports_dir / "classification_report.txt").write_text(
        report,
        encoding="utf-8",
    )

    # -------------------------------------------------
    # 3. Confusion matrix.
    # -------------------------------------------------

    matrix = confusion_matrix(
        y_test,
        test_predictions,
        labels=[0, 1],
    )

    plt.figure(figsize=(7, 6))

    plt.imshow(matrix, interpolation="nearest", cmap="Blues")
    plt.title("URLSentry - Confusion Matrix")
    plt.colorbar()

    plt.xticks([0, 1], ["Legitimate", "Phishing"])
    plt.yticks([0, 1], ["Legitimate", "Phishing"])

    plt.xlabel("Predicted Label")
    plt.ylabel("Actual Label")

    for row in range(2):
        for column in range(2):
            plt.text(
                column,
                row,
                str(matrix[row, column]),
                ha="center",
                va="center",
                fontsize=13,
            )

    plt.tight_layout()
    plt.savefig(
        figures_dir / "confusion_matrix.png",
        dpi=300,
    )
    plt.close()

    # -------------------------------------------------
    # 4. ROC curve.
    # -------------------------------------------------

    fpr, tpr, _ = roc_curve(
        y_test,
        test_probabilities,
    )

    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, label=f"ROC-AUC = {metrics['roc_auc']:.3f}")
    plt.plot([0, 1], [0, 1], linestyle="--")

    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("URLSentry - ROC Curve")
    plt.legend()
    plt.tight_layout()

    plt.savefig(
        figures_dir / "roc_curve.png",
        dpi=300,
    )
    plt.close()

    # -------------------------------------------------
    # 5. Precision-recall curve.
    # -------------------------------------------------

    precision_values, recall_values, _ = (
        precision_recall_curve(
            y_test,
            test_probabilities,
        )
    )

    plt.figure(figsize=(8, 6))
    plt.plot(
        recall_values,
        precision_values,
        label=f"PR-AUC = {metrics['pr_auc']:.3f}",
    )

    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.title("URLSentry - Precision-Recall Curve")
    plt.legend()
    plt.tight_layout()

    plt.savefig(
        figures_dir / "precision_recall_curve.png",
        dpi=300,
    )
    plt.close()

    # -------------------------------------------------
    # 6. Error analysis.
    # -------------------------------------------------

    error_df = test_df[["url", "is_phishing"]].copy()

    error_df["predicted_label"] = test_predictions
    error_df["phishing_score"] = test_probabilities

    error_df["result"] = np.where(
        error_df["is_phishing"] == error_df["predicted_label"],
        "correct",
        "incorrect",
    )

    error_df["error_type"] = np.select(
        [
            (error_df["is_phishing"] == 1)
            & (error_df["predicted_label"] == 0),

            (error_df["is_phishing"] == 0)
            & (error_df["predicted_label"] == 1),
        ],
        [
            "false_negative",
            "false_positive",
        ],
        default="correct",
    )

    error_df.to_csv(
        reports_dir / "test_predictions.csv",
        index=False,
    )

    error_df[error_df["result"] == "incorrect"].to_csv(
        reports_dir / "misclassified_urls.csv",
        index=False,
    )

    print("\n========== ERROR ANALYSIS ==========")
    print(error_df["error_type"].value_counts())

    # -------------------------------------------------
    # 7. Feature importance using permutation importance.
    # -------------------------------------------------

    # Use a manageable validation sample for performance.
    sample_size = min(5000, len(X_validation))

    importance_sample = X_validation.sample(
        n=sample_size,
        random_state=42,
    )

    importance_labels = y_validation.loc[
        importance_sample.index
    ]

    print("\n[INFO] Calculating permutation importance...")

    importance = permutation_importance(
        model,
        importance_sample,
        importance_labels,
        scoring="f1",
        n_repeats=3,
        random_state=42,
        n_jobs=2,
    )

    importance_df = pd.DataFrame({
        "feature": feature_columns,
        "importance_mean": importance.importances_mean,
        "importance_std": importance.importances_std,
    })

    importance_df = importance_df.sort_values(
        "importance_mean",
        ascending=False,
    )

    importance_df.to_csv(
        reports_dir / "feature_importance.csv",
        index=False,
    )

    top_features = importance_df.head(15).sort_values(
        "importance_mean"
    )

    plt.figure(figsize=(10, 7))

    plt.barh(
        top_features["feature"],
        top_features["importance_mean"],
    )

    plt.xlabel("Mean decrease in F1 after permutation")
    plt.title("URLSentry - Permutation Feature Importance")
    plt.tight_layout()

    plt.savefig(
        figures_dir / "feature_importance.png",
        dpi=300,
    )
    plt.close()

    # -------------------------------------------------
    # 8. Save deployment metadata.
    # -------------------------------------------------

    metadata = {
        "model_name": "best_model",
        "threshold": float(best_threshold),
        "positive_class": "phishing",
        "negative_class": "legitimate",
        "features": feature_columns,
        "test_metrics": metrics,
    }

    metadata_path = models_dir / "model_config.json"

    metadata_path.write_text(
        json.dumps(metadata, indent=4),
        encoding="utf-8",
    )

    print("\n========== OUTPUT FILES ==========")

    print(f"Final metrics: {reports_dir / 'final_test_metrics.csv'}")
    print(f"Classification report: {reports_dir / 'classification_report.txt'}")
    print(f"Feature importance: {reports_dir / 'feature_importance.csv'}")
    print(f"Model configuration: {metadata_path}")

    print("\n[OK] Advanced evaluation completed.")


if __name__ == "__main__":
    evaluate_model()
