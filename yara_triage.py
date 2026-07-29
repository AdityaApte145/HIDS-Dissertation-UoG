import os
import yara
import shutil

def is_linux_compatible(file_path: str) -> bool:
    """Reads the rule file to filter out Windows/Mac dependencies and broken includes."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read().lower()
            
            # Reject rules with external Windows/Mac C-module dependencies
            if 'import "pe"' in content or 'import "macho"' in content:
                return False
                
            # Reject rules relying on relative include paths
            if 'include "' in content:
                return False
                
            # Reject rules explicitly tagged for other OS environments
            if any(keyword in file_path.lower() for keyword in ['windows', 'apt_win', 'maldoc', 'macos']):
                return False
                
            return True
    except Exception:
        return False

def triage_rules(raw_dirs: list, active_dir: str):
    os.makedirs(active_dir, exist_ok=True)
    
    success_count = 0
    fail_count = 0
    skipped_count = 0

    print("[+] Starting YARA rule triage for Linux Host...")

    for raw_dir in raw_dirs:
        for root, _, files in os.walk(raw_dir):
            for file in files:
                if file.endswith(".yar") or file.endswith(".yara"):
                    file_path = os.path.join(root, file)
                    
                    # 1. Pre-filter for Linux compatibility
                    if not is_linux_compatible(file_path):
                        skipped_count += 1
                        continue
                    
                    # 2. Test Compilation
                    try:
                        yara.compile(filepath=file_path)
                        # If it compiles without SyntaxErrors, it's safe for the engine
                        safe_name = f"{os.path.basename(root)}_{file}" # Prevent naming collisions
                        shutil.copy(file_path, os.path.join(active_dir, safe_name))
                        success_count += 1
                    
                    except yara.SyntaxError:
                        fail_count += 1

    print("\n[=] Triage Complete [=]")
    print(f"  -> Active Linux Rules Deployed: {success_count}")
    print(f"  -> Skipped (Windows/Mac):       {skipped_count}")
    print(f"  -> Failed (Syntax/Missing Mod): {fail_count}")

if __name__ == "__main__":
    # The raw directories downloaded
    RAW_SOURCES = ["./raw_roth_rules", "./raw_yara_rules"]
    
    # The clean directory the hids_engine.py is configured to read from
    ACTIVE_ENGINE_DIR = "./yara_rules"
    
    # Clean the active directory if it already exists to prevent duplicates
    if os.path.exists(ACTIVE_ENGINE_DIR):
        shutil.rmtree(ACTIVE_ENGINE_DIR)
        
    triage_rules(RAW_SOURCES, ACTIVE_ENGINE_DIR)