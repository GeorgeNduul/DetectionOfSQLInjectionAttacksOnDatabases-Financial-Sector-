import os
import pandas as pd

# Relative paths so the script works on any machine
master_csv_path = os.path.join("data", "financial_sqli_master_10k.csv")
output_base_dir = os.path.join("data", "raw")

print("Synchronizing segmented data folders with updated master records...")

try:
    # Ingest the master dataset containing automated primary keys
    df = pd.read_csv(master_csv_path)

    # Create target sub-directories if they don't exist
    normal_dir = os.path.join(output_base_dir, "normal")
    malicious_dir = os.path.join(output_base_dir, "malicious")

    os.makedirs(normal_dir, exist_ok=True)
    os.makedirs(malicious_dir, exist_ok=True)

    # Separate rows based on the boolean malicious label
    normal_df = df[df["is_malicious"] == False]
    malicious_df = df[df["is_malicious"] == True]

    # Save the partitions
    normal_file_path = os.path.join(normal_dir, "legitimate_queries_10k.csv")
    malicious_file_path = os.path.join(malicious_dir, "attack_queries_10k.csv")

    normal_df.to_csv(normal_file_path, index=False)
    malicious_df.to_csv(malicious_file_path, index=False)

    # Output validation report
    print("\n" + "=" * 60)
    print("SUCCESS: LOCAL DATA REPOSITORY SYNCHRONIZED")
    print("=" * 60)
    print(f"• Source Master Rows:      {len(df)}")
    print(f"• Updated 'data/raw/normal/' file layout:    {len(normal_df)} rows")
    print(f"• Updated 'data/raw/malicious/' file layout: {len(malicious_df)} rows")
    print("-" * 60)
    print("Verified Attack Profile Counts with active Primary Keys:")
    print(malicious_df["attack_type"].value_counts())
    print("=" * 60)

except Exception as e:
    print(f"CRITICAL Error during folder sync: {e}")