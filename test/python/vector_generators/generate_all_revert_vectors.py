#!/usr/bin/env python3
"""
Generate all revert test vectors for PQRegistry tests.
This script generates all revert test vectors used for testing error conditions.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

# Vector generators for revert tests
REVERT_VECTOR_GENERATORS = [
    {
        "name": "Confirm Registration Reverts",
        "script": "revert/generate_confirm_revert_vectors.py",
        "output": "revert/confirm_registration_revert_vectors.json",
        "description": "Revert test vectors for confirmRegistration function"
    },
    {
        "name": "Missing Confirm Revert Vectors",
        "script": "revert/generate_missing_confirm_revert_vectors.py",
        "output": "revert/missing_confirm_revert_vectors.json",
        "description": "Additional revert test vectors for missing confirm scenarios"
    },
    {
        "name": "Comprehensive Revert Vectors",
        "script": "revert/revert_vector_generator.py",
        "output": "revert/comprehensive_revert_vectors.json",
        "description": "Comprehensive revert test vectors for all functions"
    },
    {
        "name": "Unregistration Confirmation Revert Vectors",
        "script": "revert/unregistration_confirmation_revert_generator.py",
        "output": "revert/unregistration_confirmation_revert_vectors.json",
        "description": "Revert test vectors for confirmUnregistration function"
    },
    {
        "name": "Unregistration Revert Vectors",
        "script": "revert/unregistration_revert_generator.py",
        "output": "revert/unregistration_revert_vectors.json",
        "description": "Revert test vectors for submitUnregistrationIntent function"
    },
    {
        "name": "Change ETH Revert Vectors",
        "script": "revert/change_eth_revert_generator.py",
        "output": "revert/change_eth_revert_vectors.json",
        "description": "Revert test vectors for changeETHAddress function"
    },
    {
        "name": "Change ETH Removal Revert Vectors",
        "script": "revert/change_eth_removal_revert_generator.py",
        "output": "revert/change_eth_removal_revert_vectors.json",
        "description": "Revert test vectors for changeETHAddress removal scenarios"
    }
]

def run_generator(generator, force=False):
    """Run a single vector generator."""
    script_path = Path(__file__).parent / generator["script"]
    output_path = Path(__file__).parent.parent.parent / "test" / "test_vectors" / generator["output"]
    venv_path = Path(__file__).parent.parent.parent.parent / "ETHFALCON" / "python-ref" / "myenv"

    print(f"Running: {generator['name']}")
    print(f"Script: {script_path}")
    print(f"Output: {output_path}")

    # Check if output already exists
    if output_path.exists() and not force:
        print(f"Output file already exists: {output_path}")
        print("Use --force to regenerate")
        return False

    try:
        # Change to the script directory
        script_dir = script_path.parent
        os.chdir(script_dir)

        # Run the script with venv activated
        bash_cmd = f"source '{venv_path}/bin/activate' && python3 '{script_path.name}'"
        result = subprocess.run(bash_cmd, shell=True, capture_output=True, text=True, check=True)

        print(f"✅ Successfully generated: {generator['name']}")
        if result.stdout:
            print(result.stdout)
        return True

    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to generate: {generator['name']}")
        print(f"Error: {e}")
        if e.stdout:
            print(f"stdout: {e.stdout}")
        if e.stderr:
            print(f"stderr: {e.stderr}")
        return False
    except Exception as e:
        print(f"❌ Error running {generator['name']}: {e}")
        return False

def main():
    """Generate all revert test vectors."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate all revert test vectors")
    parser.add_argument("--force", action="store_true", 
                       help="Force regeneration of existing files")
    args = parser.parse_args()
    
    print("=" * 60)
    print("GENERATING ALL REVERT TEST VECTORS")
    print("=" * 60)
    
    # Get the script directory
    script_dir = Path(__file__).parent
    os.chdir(script_dir)
    
    total_generators = len(REVERT_VECTOR_GENERATORS)
    successful_generators = 0
    
    for i, generator in enumerate(REVERT_VECTOR_GENERATORS, 1):
        print(f"\n[{i}/{total_generators}] {generator['name']}")
        print(f"Description: {generator['description']}")
        print("-" * 40)
        
        if run_generator(generator, args.force):
            successful_generators += 1
    
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total generators: {total_generators}")
    print(f"Successful: {successful_generators}")
    print(f"Failed: {total_generators - successful_generators}")
    print(f"Success rate: {(successful_generators/total_generators)*100:.1f}%")
    
    if successful_generators == total_generators:
        print("\n🎉 All revert test vectors generated successfully!")
    else:
        print(f"\n⚠️  {total_generators - successful_generators} generators failed")
        sys.exit(1)

if __name__ == "__main__":
    main() 