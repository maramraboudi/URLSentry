from pathlib import Path

import pandas as pd
from ucimlrepo import fetch_ucirepo


def download_dataset():
    """Download the original PhiUSIIL dataset from UCI."""

    project_root = Path(__file__).resolve().parents[2]
    output_dir = project_root / "data" / "raw"

    output_dir.mkdir(parents=True, exist_ok=True)

    output_file = output_dir / "phiusiil_original.csv"

    print("[INFO] Connecting to the UCI Machine Learning Repository...")

    dataset = fetch_ucirepo(id=967)

    print("[INFO] Dataset downloaded successfully.")
    print("[INFO] Combining features and target labels...")

    features = dataset.data.features
    targets = dataset.data.targets

    data = pd.concat([features, targets], axis=1)

    print("[INFO] Saving the original dataset...")

    data.to_csv(output_file, index=False)

    print("\n========== DOWNLOAD SUMMARY ==========")
    print(f"Output file: {output_file}")
    print(f"Number of records: {len(data)}")
    print(f"Number of columns: {len(data.columns)}")
    print(f"File size: {output_file.stat().st_size / (1024 * 1024):.2f} MB")

    print("\nAvailable columns:")
    print(data.columns.tolist())

    print("\nDataset saved successfully!")


if __name__ == "__main__":
    download_dataset()
