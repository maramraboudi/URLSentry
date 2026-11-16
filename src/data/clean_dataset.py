from pathlib import Path

import pandas as pd


def clean_dataset():
    project_root = Path(__file__).resolve().parents[2]

    input_path = project_root / "data" / "raw" / "phiusiil_original.csv"
    output_dir = project_root / "data" / "processed"
    output_path = output_dir / "urls_clean.csv"

    if not input_path.exists():
        raise FileNotFoundError(f"Dataset not found: {input_path}")

    output_dir.mkdir(parents=True, exist_ok=True)

    print("[INFO] Loading original dataset...")
    df = pd.read_csv(input_path)

    url_column = next(
        (c for c in df.columns if c.lower() == "url"),
        None,
    )

    label_column = next(
        (c for c in df.columns if c.lower() == "label"),
        None,
    )

    if url_column is None or label_column is None:
        raise ValueError("Required URL or label column is missing.")

    df = df[[url_column, label_column]].copy()
    df.columns = ["url", "original_label"]

    print(f"[INFO] Original records: {len(df)}")

    # Remove records with missing values.
    df = df.dropna(subset=["url", "original_label"])

    # Convert labels to numeric values.
    df["original_label"] = pd.to_numeric(
        df["original_label"],
        errors="coerce",
    )

    df = df.dropna(subset=["original_label"])

    # Keep only the two expected original classes.
    df = df[df["original_label"].isin([0, 1])]

    # Remove empty URL strings.
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"] != ""]

    # Remove URLs with contradictory labels.
    conflicting_urls = (
        df.groupby("url")["original_label"]
        .nunique()
    )

    conflicting_urls = conflicting_urls[
        conflicting_urls > 1
    ].index

    print(
        "[INFO] URLs with conflicting labels:",
        len(conflicting_urls),
    )

    df = df[~df["url"].isin(conflicting_urls)]

    # Remove exact duplicate URLs.
    df = df.drop_duplicates(subset=["url"])

    # Convert source labels:
    # 0 = phishing, 1 = legitimate
    # Our convention: 1 = phishing, 0 = legitimate.
    df["is_phishing"] = (
        df["original_label"] == 0
    ).astype(int)

    # Keep only the columns needed by our system.
    df = df[["url", "is_phishing"]]

    df = df.reset_index(drop=True)

    df.to_csv(output_path, index=False)

    print("\n========== CLEANING SUMMARY ==========")
    print(f"Clean records: {len(df)}")
    print(f"Removed records: {len(pd.read_csv(input_path)) - len(df)}")
    print(f"Saved to: {output_path}")

    print("\n========== FINAL CLASS DISTRIBUTION ==========")
    print(df["is_phishing"].value_counts())

    print("\n========== CLASS PERCENTAGES ==========")
    print(
        (df["is_phishing"].value_counts(normalize=True) * 100)
        .round(2)
    )

    print("\n[OK] Dataset preprocessing completed.")


if __name__ == "__main__":
    clean_dataset()
