from pathlib import Path

import pandas as pd

from src.features.url_features import extract_url_features


def build_features():
    project_root = Path(__file__).resolve().parents[2]

    input_path = project_root / "data" / "processed" / "urls_clean.csv"
    output_path = project_root / "data" / "processed" / "urls_features.csv"

    if not input_path.exists():
        raise FileNotFoundError(
            "Clean dataset not found. Run the preprocessing phase first."
        )

    print("[INFO] Loading cleaned dataset...")

    df = pd.read_csv(input_path)

    print(f"[INFO] Processing {len(df)} URLs...")

    # Extract features for every URL.
    feature_records = [
        extract_url_features(url)
        for url in df["url"]
    ]

    features_df = pd.DataFrame(feature_records)

    # Preserve URLs for traceability and keep the target.
    result = pd.concat(
        [
            df[["url"]].reset_index(drop=True),
            features_df.reset_index(drop=True),
            df[["is_phishing"]].reset_index(drop=True),
        ],
        axis=1,
    )

    result.to_csv(output_path, index=False)

    print("\n========== FEATURE GENERATION SUMMARY ==========")
    print(f"Processed URLs: {len(result)}")
    print(f"Generated features: {len(features_df.columns)}")
    print(f"Total columns: {len(result.columns)}")
    print(f"Output: {output_path}")

    print("\n========== FEATURE NAMES ==========")

    for feature in features_df.columns:
        print(f"- {feature}")

    print("\n========== FEATURE PREVIEW ==========")
    print(features_df.head())

    print("\n[OK] Feature generation completed.")


if __name__ == "__main__":
    build_features()
