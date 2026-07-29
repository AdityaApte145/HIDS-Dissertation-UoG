import csv
import sqlite3
import time
from pathlib import Path


def create_and_populate_db(csv_path: str, db_path: str = "hids_signatures.db"):
    csv_file = Path(csv_path)

    if not csv_file.exists():
        print(f"[-] Error: Target CSV file not found at: {csv_file.resolve()}")
        return

    print(f"[*] Starting database creation pipeline using source: {csv_file.name}")
    start_time = time.time()

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("DROP TABLE IF EXISTS mal_hashes;")

    cursor.execute(
        """
        CREATE TABLE mal_hashes (
            sha256 TEXT PRIMARY KEY,
            malware_name TEXT NOT NULL,
            added_on TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """
    )

    cursor.execute("PRAGMA synchronous = OFF;")
    cursor.execute("PRAGMA journal_mode = MEMORY;")

    batch_size = 50000
    hash_batch = []
    total_inserted = 0

    try:
        with open(csv_file, mode="r", encoding="utf-8", errors="ignore") as f:
            # FIX: Added skipinitialspace=True to handle the space after the comma
            reader = csv.reader(f, delimiter=",", quotechar='"', skipinitialspace=True)

            for row in reader:
                if not row or row[0].startswith("#"):
                    continue

                # Strip quotes just in case the header row is formatted weirdly
                if row[0].replace('"', '').strip() == "first_seen_utc":
                    continue

                try:
                    # FIX: Aggressively remove any rogue quotes that slipped through
                    sha256 = row[1].replace('"', '').strip().lower()
                    
                    raw_sig = row[8].replace('"', '').strip()
                    signature = raw_sig if raw_sig else "Unidentified_Malware"

                    if len(sha256) == 64:
                        hash_batch.append((sha256, signature))

                except IndexError:
                    continue

                if len(hash_batch) >= batch_size:
                    cursor.executemany(
                        "INSERT OR IGNORE INTO mal_hashes (sha256, malware_name) VALUES (?, ?)",
                        hash_batch,
                    )
                    total_inserted += len(hash_batch)
                    print(f"[+] Bulk transaction committed: {total_inserted} records processed...")
                    hash_batch = []

            if hash_batch:
                cursor.executemany(
                    "INSERT OR IGNORE INTO mal_hashes (sha256, malware_name) VALUES (?, ?)",
                    hash_batch,
                )
                total_inserted += len(hash_batch)

        conn.commit()

        print("[*] Enforcing B-Tree schema indices for O(1) detection routing...")
        cursor.execute("CREATE INDEX idx_hashes ON mal_hashes (sha256);")
        conn.commit()

        elapsed_time = time.time() - start_time
        print(f"\n[+] Database fully built: {db_path}")
        print(f"[+] Total Signatures Armed: {total_inserted} in {elapsed_time:.2f} seconds.")

    except Exception as e:
        print(f"[-] Critical system compilation error encountered: {e}")
        conn.rollback()
    finally:
        conn.close()


if __name__ == "__main__":
    TARGET_CSV = "full.csv"
    create_and_populate_db(TARGET_CSV)