from pathlib import Path

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns


def explore_dataset():
    project_root = Path(__file__).resolve().parents[2]

    dataset_path = (
        project_root / "data" / "processed" / "urls_features.csv"
    )

    figures_dir = project_root / "reports" / "figures"
    reports_dir = project_root / "reports" / "eda"

    figures_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    if not dataset_path.exists():
        raise FileNotFoundError(
            "Feature dataset not found. Run Phase 4 first."
        )

    print("[INFO] Loading feature dataset...")

    df = pd.read_csv(dataset_path)

    feature_columns = [
        column
        for column in df.columns
        if column not in ["url", "is_phishing"]
    ]

    print("\n========== DATASET SUMMARY ==========")
    print(f"Total records: {len(df)}")
    print(f"Total features: {len(feature_columns)}")

    print("\n========== CLASS DISTRIBUTION ==========")

    distribution = df["is_phishing"].value_counts().sort_index()

    print(distribution.rename({
        0: "Legitimate",
        1: "Phishing",
    }))

    percentages = (
        df["is_phishing"]
        .value_counts(normalize=True)
        .sort_index() * 100
    )

    print("\nClass percentages:")
    print(percentages.round(2))

    print("\n========== FEATURE STATISTICS ==========")

    statistics = df[feature_columns].describe().T

    statistics.to_csv(
        reports_dir / "feature_statistics.csv"
    )

    print(statistics.round(3).to_string())

    # Human-readable labels for plots.
    df["url_type"] = df["is_phishing"].map({
        0: "Legitimate",
        1: "Phishing",
    })

    sns.set_theme(style="whitegrid")

    # 1. Class distribution.
    plt.figure(figsize=(8, 5))

    sns.countplot(
        data=df,
        x="url_type",
        hue="url_type",
        order=["Legitimate", "Phishing"],
        palette="Set2",
        legend=False,
    )

    plt.title("Legitimate vs Phishing URL Distribution")
    plt.xlabel("URL Category")
    plt.ylabel("Number of URLs")
    plt.tight_layout()

    plt.savefig(
        figures_dir / "class_distribution.png",
        dpi=300,
    )

    plt.close()

    # 2. URL length comparison.
    plt.figure(figsize=(9, 5))

    sns.boxplot(
        data=df,
        x="url_type",
        y="url_length",
        hue="url_type",
        order=["Legitimate", "Phishing"],
        palette="Set2",
        showfliers=False,
        legend=False,
    )

    plt.title("URL Length by Category")
    plt.xlabel("URL Category")
    plt.ylabel("URL Length")
    plt.tight_layout()

    plt.savefig(
        figures_dir / "url_length_comparison.png",
        dpi=300,
    )

    plt.close()

    # 3. Digit ratio comparison.
    plt.figure(figsize=(9, 5))

    sns.boxplot(
        data=df,
        x="url_type",
        y="digit_ratio",
        hue="url_type",
        order=["Legitimate", "Phishing"],
        palette="Set2",
        showfliers=False,
        legend=False,
    )

    plt.title("Digit Ratio by URL Category")
    plt.xlabel("URL Category")
    plt.ylabel("Digit Ratio")
    plt.tight_layout()

    plt.savefig(
        figures_dir / "digit_ratio_comparison.png",
        dpi=300,
    )

    plt.close()

    # 4. HTTPS usage.
    https_distribution = (
        df.groupby(["url_type", "has_https"])
        .size()
        .reset_index(name="count")
    )

    https_distribution["HTTPS"] = (
        https_distribution["has_https"]
        .map({0: "No HTTPS", 1: "HTTPS"})
    )

    plt.figure(figsize=(8, 5))

    sns.barplot(
        data=https_distribution,
        x="url_type",
        y="count",
        hue="HTTPS",
    )

    plt.title("HTTPS Usage by URL Category")
    plt.xlabel("URL Category")
    plt.ylabel("Number of URLs")
    plt.tight_layout()

    plt.savefig(
        figures_dir / "https_distribution.png",
        dpi=300,
    )

    plt.close()

    # 5. Suspicious keyword comparison.
    plt.figure(figsize=(9, 5))

    sns.boxplot(
        data=df,
        x="url_type",
        y="suspicious_keyword_count",
        hue="url_type",
        order=["Legitimate", "Phishing"],
        palette="Set2",
        showfliers=False,
        legend=False,
    )

    plt.title("Suspicious Keyword Count by URL Category")
    plt.xlabel("URL Category")
    plt.ylabel("Keyword Count")
    plt.tight_layout()

    plt.savefig(
        figures_dir / "keyword_comparison.png",
        dpi=300,
    )

    plt.close()

    # 6. Correlation heatmap.
    correlation = df[feature_columns + ["is_phishing"]].corr()

    plt.figure(figsize=(20, 16))

    sns.heatmap(
        correlation,
        cmap="coolwarm",
        center=0,
        linewidths=0.2,
    )

    plt.title("URL Feature Correlation Matrix")
    plt.tight_layout()

    plt.savefig(
        figures_dir / "correlation_matrix.png",
        dpi=300,
    )

    plt.close()

    # 7. Mean feature comparison by class.
    class_means = (
        df.groupby("url_type")[feature_columns]
        .mean()
        .T
    )

    class_means.to_csv(
        reports_dir / "feature_class_comparison.csv"
    )

    print("\n========== EDA OUTPUTS ==========")

    for file in sorted(figures_dir.glob("*.png")):
        print(f"[FIGURE] {file.name}")

    print("\n[OK] Exploratory analysis completed.")


if __name__ == "__main__":
    explore_dataset()
