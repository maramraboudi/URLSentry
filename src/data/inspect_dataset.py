from pathlib import Path

import pandas as pd


def inspect_dataset():
    project_root = Path(__file__).resolve().parents[2]
    dataset_path = project_root / "data" / "raw" / "phiusiil_original.csv"

    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")

    df = pd.read_csv(dataset_path)

    print("\n========== DATASET OVERVIEW ==========")
    print(f"Rows: {len(df)}")
    print(f"Columns: {len(df.columns)}")
    print(f"Memory usage: {df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")

    print("\n========== COLUMN NAMES ==========")
    for column in df.columns:
        print(f"- {column}")

    print("\n========== DATA TYPES ==========")
    print(df.dtypes)

    print("\n========== MISSING VALUES ==========")
    missing = df.isnull().sum()
    print(missing[missing > 0] if missing.any() else "No missing values.")

    print("\n========== DUPLICATE RECORDS ==========")
    print(f"Exact duplicate rows: {df.duplicated().sum()}")

    print("\n========== URL ANALYSIS ==========")
    url_column = next(
        (c for c in df.columns if c.lower() == "url"),
        None,
    )

    if url_column is None:
        raise ValueError("URL column was not found.")

    print(f"URL column: {url_column}")
    print("Example URLs:")
    print(df[url_column].head(5).to_string(index=False))

    print("\n========== LABEL ANALYSIS ==========")
    label_column = next(
        (c for c in df.columns if c.lower() == "label"),
        None,
    )

    if label_column is None:
        raise ValueError("Label column was not found.")

    print("Original label distribution:")
    print(df[label_column].value_counts(dropna=False))

    print("\n========== URL-LABEL CONSISTENCY ==========")
    conflicts = (
        df.groupby(url_column)[label_column]
        .nunique()
        .gt(1)
        .sum()
    )

    print(f"URLs with conflicting labels: {conflicts}")

    print("\nInspection completed.")


if __name__ == "__main__":
    inspect_dataset()
