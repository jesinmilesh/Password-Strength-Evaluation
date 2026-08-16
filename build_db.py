import os
import sqlite3
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(BASE_DIR, 'database')
DB_PATH = os.path.join(DB_DIR, 'passwords.db')
DATASETS_DIR = os.path.join(BASE_DIR, 'datasets')

def build_password_database():
    os.makedirs(DB_DIR, exist_ok=True)
    
    print("==================================================")
    print("  BUILDING OPTIMIZED SQLITE PASSWORD DATABASE")
    print(f"  Target DB Path: {DB_PATH}")
    print("==================================================")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Enable PRAGMAs for fast bulk loading
    cursor.execute("PRAGMA synchronous = OFF;")
    cursor.execute("PRAGMA journal_mode = MEMORY;")
    cursor.execute("PRAGMA cache_size = 100000;")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            password TEXT PRIMARY KEY
        );
    """)
    conn.commit()

    total_inserted = 0
    batch = []
    batch_size = 100000

    if os.path.exists(DATASETS_DIR):
        for filename in sorted(os.listdir(DATASETS_DIR)):
            if filename.endswith('.txt'):
                file_path = os.path.join(DATASETS_DIR, filename)
                print(f"  Processing {filename}...")
                encoding = 'latin-1' if 'global_breach' in filename else 'utf-8'
                file_count = 0
                with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                    for line in f:
                        pw = line.strip().lower()
                        if pw:
                            batch.append((pw,))
                            file_count += 1
                            if len(batch) >= batch_size:
                                cursor.executemany("INSERT OR IGNORE INTO passwords (password) VALUES (?)", batch)
                                conn.commit()
                                total_inserted += len(batch)
                                batch.clear()
                                sys.stdout.write(f"\r    Inserted {total_inserted:,} passwords...")
                                sys.stdout.flush()
                print(f"\n    Completed {filename}: {file_count:,} entries processed.")

    if batch:
        cursor.executemany("INSERT OR IGNORE INTO passwords (password) VALUES (?)", batch)
        conn.commit()
        total_inserted += len(batch)
        batch.clear()

    print(f"\n  Creating Index idx_password on passwords(password)...")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_password ON passwords(password);")
    conn.commit()

    # Re-enable standard PRAGMAs
    cursor.execute("PRAGMA synchronous = NORMAL;")
    cursor.execute("PRAGMA journal_mode = WAL;")

    cursor.execute("SELECT COUNT(*) FROM passwords;")
    final_count = cursor.fetchone()[0]

    conn.close()

    print("==================================================")
    print("  SQLITE PASSWORD DATABASE BUILD COMPLETE!")
    print(f"  Total Unique Passwords in DB: {final_count:,}")
    print(f"  Database File Size: {os.path.getsize(DB_PATH) / (1024*1024):.1f} MB")
    print("==================================================")

if __name__ == '__main__':
    build_password_database()
