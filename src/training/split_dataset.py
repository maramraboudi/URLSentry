from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd
import tldextract

from sklearn.model_selection import GroupShuffleSplit


def extract_domain_group(url):
    """Return a domain grouping key without making network requests."""

    value = str(url).strip()

    if "://" not in value:
        value = "//" + value

    try:
        hostname = urlsplit(value).hostname or ""
    except ValueError:
        hostname = ""

    hostname = hostname.lower().rstrip(".")

    if not hostname:
        return "invalid:" + str(url)

    try:
        extracted = tldextract.extract(hostname)

        registered_domain = extracted.top_domain_under_public_suffix

        if registered_domain:
            return registered_domain.lower()

    except Exception:
        pass

    # Fallback for IP addresses, localhost, or unusual hostnames.
    return hostname


def split_dataset():
    project_root = Path(__file__).resolve().parents[2]

    input_path = (
        project_root / "data" / "processed" / "urls_features.csv"
    )

    output_dir = project_root / "data" / "processed" / "splits"
    output_dir.mkdir(parents=True, exist_ok=True)

    if not input_path.exists():
        raise FileNotFoundError(
            "Feature dataset not found. Run Phase 4 first."
        )

    print("[INFO] Loading feature dataset...")

    df = pd.read_csv(input_path)

    if df["is_phishing"].nunique() != 2:
        raise ValueError("Both target classes must be present.")

    print("[INFO] Creating domain groups...")

    groups = df["url"].apply(extract_domain_group)

    # First split: 80% development, 20% final test.
    first_split = GroupShuffleSplit(
        n_splits=1,
        test_size=0.20,
        random_state=42,
    )

    development_indices, test_indices = next(
        first_split.split(df, df["is_phishing"], groups)
    )

    development_df = df.iloc[development_indices].copy()
    test_df = df.iloc[test_indices].copy()

    development_groups = groups.iloc[development_indices]
    test_groups = groups.iloc[test_indices]

    # Second split: 75% of development for training,
    # 25% of development for validation.
    # Overall: approximately 60% train, 20% validation, 20% test.
    second_split = GroupShuffleSplit(
        n_splits=1,
        test_size=0.25,
        random_state=42,
    )

    train_indices, validation_indices = next(
        second_split.split(
            development_df,
            development_df["is_phishing"],
            development_groups,
        )
    )

    train_df = development_df.iloc[train_indices].copy()
    validation_df = development_df.iloc[validation_indices].copy()

    train_groups = set(
        development_groups.iloc[train_indices]
    )

    validation_groups = set(
        development_groups.iloc[validation_indices]
    )

    test_groups = set(test_groups)

    # Verify that no domain crosses dataset boundaries.
    assert train_groups.isdisjoint(validation_groups)
    assert train_groups.isdisjoint(test_groups)
    assert validation_groups.isdisjoint(test_groups)

    # Save all splits.
    train_df.to_csv(output_dir / "train.csv", index=False)
    validation_df.to_csv(output_dir / "validation.csv", index=False)
    test_df.to_csv(output_dir / "test.csv", index=False)

    print("\n========== SPLIT SUMMARY ==========")

    for name, split in [
        ("TRAIN", train_df),
        ("VALIDATION", validation_df),
        ("TEST", test_df),
    ]:
        print(f"\n{name}")
        print(f"Records: {len(split)}")
        print(
            "Phishing:",
            int(split["is_phishing"].sum()),
        )
        print(
            "Legitimate:",
            int((split["is_phishing"] == 0).sum()),
        )
        print(
            "Phishing percentage:",
            round(split["is_phishing"].mean() * 100, 2),
            "%",
        )

    print("\n========== DOMAIN LEAKAGE CHECK ==========")
    print("Training and validation overlap:", len(train_groups & validation_groups))
    print("Training and test overlap:", len(train_groups & test_groups))
    print("Validation and test overlap:", len(validation_groups & test_groups))

    print("\n[OK] Domain-aware splitting completed.")


if __name__ == "__main__":
    split_dataset()
