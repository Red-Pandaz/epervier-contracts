#!/usr/bin/env python3
"""
Cleanup and regenerate all test vectors.

This script deletes all existing test vectors and then regenerates them
using the generate_all_vectors.py script.

Usage:
    python3 cleanup_and_regenerate.py [--actors-only]

Options:
    --actors-only: Only generate vectors for a subset of actors (for testing)
"""

import shutil
import sys
import subprocess
from pathlib import Path
import argparse

def cleanup_test_vectors():
    """Delete all test vectors from the test_vectors directory."""
    project_root = Path(__file__).resolve().parents[3]  # epervier-registry
    test_vectors_dir = project_root / "test/test_vectors"
    
    if test_vectors_dir.exists():
        print(f"🗑️  Deleting test vectors directory: {test_vectors_dir}")
        shutil.rmtree(test_vectors_dir)
        print("✅ Test vectors directory deleted")
    else:
        print("ℹ️  Test vectors directory does not exist, nothing to delete")

def regenerate_vectors(actors_only: bool = False):
    """Regenerate all test vectors using generate_all_vectors.py."""
    print("\n🔄 Regenerating all test vectors...")
    
    cmd = [sys.executable, "generate_all_vectors.py", "--force"]
    if actors_only:
        cmd.append("--actors-only")
    
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=Path(__file__).parent)
    
    if result.returncode == 0:
        print("✅ All test vectors regenerated successfully!")
        return True
    else:
        print("❌ Failed to regenerate test vectors")
        return False

def main():
    """Main function to cleanup and regenerate test vectors."""
    parser = argparse.ArgumentParser(description="Cleanup and regenerate all test vectors")
    parser.add_argument("--actors-only", action="store_true", 
                       help="Only generate vectors for a subset of actors (for testing)")
    
    args = parser.parse_args()
    
    print("🧹 PQRegistry Test Vector Cleanup and Regeneration")
    print("=" * 60)
    
    # Step 1: Cleanup existing test vectors
    print("\n📋 Step 1: Cleaning up existing test vectors")
    cleanup_test_vectors()
    
    # Step 2: Regenerate all test vectors
    print("\n📋 Step 2: Regenerating all test vectors")
    success = regenerate_vectors(actors_only=args.actors_only)
    
    if success:
        print("\n🎉 Cleanup and regeneration completed successfully!")
        sys.exit(0)
    else:
        print("\n❌ Cleanup and regeneration failed!")
        sys.exit(1)

if __name__ == "__main__":
    main() 