#!/usr/bin/env python3
"""
Production test vector generator for PQRegistry

This script generates test vectors using the production actors (kyle, luke, marie, nancy, oscar)
and production domain separators.

Usage:
    python3 generate_production_vectors.py [--force]

Options:
    --force: Regenerate all vectors even if they exist
"""

import json
import subprocess
import sys
import shutil
from pathlib import Path
from typing import List, Dict, Any
import argparse

# Get the project root directory
PROJECT_ROOT = Path(__file__).resolve().parents[4]  # epervier-contracts
PRODUCTION_VECTORS_DIR = PROJECT_ROOT / "test/test_vectors/production"
# Use the virtual environment Python for running generators
VENV_PYTHON = PROJECT_ROOT / "ETHFALCON/python-ref/myenv/bin/python3"

# Production vector generators
PRODUCTION_GENERATORS = [
    {
        "name": "Production Registration Intent Vectors",
        "script": "register/registration_intent_generator.py",
        "output": "production/register/registration_intent_vectors.json",
        "description": "Test vectors for submitRegistrationIntent function (production actors)"
    },
    {
        "name": "Production Registration Confirmation Vectors",
        "script": "register/registration_confirmation_generator.py",
        "output": "production/register/registration_confirmation_vectors.json",
        "description": "Test vectors for confirmRegistration function (production actors)"
    },
    {
        "name": "Production Registration Removal Vectors",
        "script": "register/registration_intent_eth_removal_generator.py",
        "output": "production/register/registration_removal_vectors.json",
        "description": "Test vectors for removeRegistrationIntentByETH function (production actors)"
    },
    {
        "name": "Production Change ETH Address Intent Vectors",
        "script": "change_eth/change_eth_address_intent_generator.py",
        "output": "production/change_eth/change_eth_address_intent_vectors.json",
        "description": "Test vectors for submitChangeETHAddressIntent function (production actors)"
    },
    {
        "name": "Production Change ETH Address Confirmation Vectors",
        "script": "change_eth/change_eth_address_confirmation_generator.py",
        "output": "production/change_eth/change_eth_address_confirmation_vectors.json",
        "description": "Test vectors for confirmChangeETHAddress function (production actors)"
    },
    {
        "name": "Production Change ETH Address Removal Vectors",
        "script": "change_eth/change_eth_address_intent_eth_removal_generator.py",
        "output": "production/change_eth/change_eth_address_removal_vectors.json",
        "description": "Test vectors for removeChangeETHAddressIntentByETH function (production actors)"
    },
    {
        "name": "Production Unregistration Intent Vectors",
        "script": "unregister/unregistration_intent_generator.py",
        "output": "production/unregister/unregistration_intent_vectors.json",
        "description": "Test vectors for submitUnregistrationIntent function (production actors)"
    },
    {
        "name": "Production Unregistration Confirmation Vectors",
        "script": "unregister/unregistration_confirmation_generator.py",
        "output": "production/unregister/unregistration_confirmation_vectors.json",
        "description": "Test vectors for confirmUnregistration function (production actors)"
    },
    {
        "name": "Production Unregistration Removal Vectors",
        "script": "unregister/unregistration_flow_with_revocation_generator.py",
        "output": "production/unregister/unregistration_removal_vectors.json",
        "description": "Test vectors for removeUnregistrationIntentByETH function (production actors)"
    },
    {
        "name": "Production PQ Transfer Vectors",
        "script": "transfer/pq_transfer_generator.py",
        "output": "production/transfer/pq_transfer_vectors.json",
        "description": "Test vectors for PQ token transfers (production actors)"
    }
]


def check_dependencies() -> bool:
    """Check if all required dependencies are available."""
    print("Checking dependencies...")
    
    # Check if production actors config exists
    actors_config_path = PROJECT_ROOT / "test" / "test_keys" / "production_actors_config.json"
    if not actors_config_path.exists():
        print(f"❌ Production actors config not found: {actors_config_path}")
        return False
    print(f"✅ Production actors config found: {actors_config_path}")
    
    # Check if sign_cli.py exists
    sign_cli_path = PROJECT_ROOT / "ETHFALCON/python-ref/sign_cli.py"
    if not sign_cli_path.exists():
        print(f"❌ Sign CLI not found: {sign_cli_path}")
        return False
    print(f"✅ Sign CLI found: {sign_cli_path}")
    
    # Check if Python virtual environment exists
    venv_python = PROJECT_ROOT / "ETHFALCON/python-ref/myenv/bin/python3"
    if not venv_python.exists():
        print(f"❌ Python virtual environment not found: {venv_python}")
        return False
    print(f"✅ Python virtual environment found: {venv_python}")
    
    # Check if production test vectors directory exists
    if not PRODUCTION_VECTORS_DIR.exists():
        print(f"Creating production test vectors directory: {PRODUCTION_VECTORS_DIR}")
        PRODUCTION_VECTORS_DIR.mkdir(parents=True, exist_ok=True)
    else:
        print(f"✅ Production test vectors directory exists: {PRODUCTION_VECTORS_DIR}")
    
    return True


def run_production_generator(generator: Dict[str, str], force: bool = False) -> bool:
    """Run a single production vector generator."""
    script_path = Path(__file__).parent / generator["script"]
    
    # Handle different output types
    if generator["output"].endswith("/") or generator["output"] == "advanced":
        # Output is a directory
        output_path = PROJECT_ROOT / "test/test_vectors" / generator["output"]
        output_exists = output_path.exists() and any(output_path.iterdir())
    else:
        # Output is a specific file
        output_path = PROJECT_ROOT / "test/test_vectors" / generator["output"]
        output_exists = output_path.exists()
    
    print(f"\n{'='*60}")
    print(f"🔄 Generating: {generator['name']}")
    print(f"📝 Description: {generator['description']}")
    print(f"📄 Script: {script_path}")
    print(f"📁 Output: {output_path}")
    print(f"{'='*60}")
    
    # Check if output already exists
    if output_exists and not force:
        print(f"⚠️  Output already exists: {output_path}")
        print("   Use --force to regenerate")
        return True
    
    # Run the generator
    try:
        cmd = [str(VENV_PYTHON), str(script_path)]
        
        print(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(Path(__file__).parent))
        
        if result.returncode == 0:
            print(f"✅ Successfully generated: {generator['name']}")
            if result.stdout:
                print("Output:")
                print(result.stdout)
            return True
        else:
            print(f"❌ Failed to generate: {generator['name']}")
            print(f"Return code: {result.returncode}")
            if result.stdout:
                print("Stdout:")
                print(result.stdout)
            if result.stderr:
                print("Stderr:")
                print(result.stderr)
            return False
            
    except Exception as e:
        print(f"❌ Exception while running {generator['name']}: {e}")
        return False


def generate_production_summary() -> None:
    """Generate a summary of all created production vectors."""
    print(f"\n{'='*60}")
    print("📊 PRODUCTION GENERATION SUMMARY")
    print(f"{'='*60}")
    
    total_generators = len(PRODUCTION_GENERATORS)
    successful_generators = 0
    
    for generator in PRODUCTION_GENERATORS:
        output_path = PROJECT_ROOT / "test/test_vectors" / generator["output"]
        
        # Handle different output types
        if generator["output"].endswith("/") or generator["output"] == "advanced":
            # Output is a directory
            if output_path.exists() and any(output_path.iterdir()):
                # Count files in directory
                file_count = len(list(output_path.glob("*.json")))
                total_size = sum(f.stat().st_size for f in output_path.glob("*.json"))
                size_kb = total_size / 1024
                print(f"✅ {generator['name']:<40} | {file_count:>2} files | {size_kb:>6.1f} KB")
                successful_generators += 1
            else:
                print(f"❌ {generator['name']:<40} | Not generated")
        else:
            # Output is a specific file
            if output_path.exists():
                # Get file size
                size = output_path.stat().st_size
                size_kb = size / 1024
                
                # Count vectors in the file
                try:
                    with open(output_path, "r") as f:
                        data = json.load(f)
                        # Get the first key (should be the vector type)
                        first_key = list(data.keys())[0]
                        vector_count = len(data[first_key])
                        print(f"✅ {generator['name']:<40} | {vector_count:>2} vectors | {size_kb:>6.1f} KB")
                        successful_generators += 1
                except Exception as e:
                    print(f"❌ {generator['name']:<40} | Error reading: {e}")
            else:
                print(f"❌ {generator['name']:<40} | Not generated")
    
    print(f"\n📈 Success Rate: {successful_generators}/{total_generators} ({successful_generators/total_generators*100:.1f}%)")
    
    if successful_generators == total_generators:
        print("🎉 All production vectors generated successfully!")
    else:
        print("⚠️  Some production vectors failed to generate. Check the output above.")


def main():
    """Main function to generate all production test vectors."""
    parser = argparse.ArgumentParser(description="Generate all production test vectors for PQRegistry")
    parser.add_argument("--force", action="store_true", help="Regenerate all vectors even if they exist")
    parser.add_argument("--check-only", action="store_true", help="Only check dependencies without generating vectors")
    parser.add_argument("--cleanup", action="store_true", help="Delete all existing production test vectors before generating new ones")
    
    args = parser.parse_args()
    
    print("🚀 PQRegistry Production Test Vector Generator")
    print("=" * 60)
    print("🎯 Using production actors: kyle, luke, marie, nancy, oscar")
    print("🎯 Using production domain separators")
    print("=" * 60)
    
    # Check dependencies
    if not check_dependencies():
        print("❌ Dependencies check failed. Please fix the issues above.")
        sys.exit(1)
    
    if args.check_only:
        print("✅ Dependencies check passed!")
        return
    
    # Cleanup existing production test vectors if requested
    if args.cleanup:
        print("\n🧹 Cleaning up existing production test vectors...")
        if PRODUCTION_VECTORS_DIR.exists():
            print(f"🗑️  Deleting production test vectors directory: {PRODUCTION_VECTORS_DIR}")
            shutil.rmtree(PRODUCTION_VECTORS_DIR)
            print("✅ Production test vectors directory deleted")
        else:
            print("ℹ️  Production test vectors directory does not exist")
    
    # Generate all production vectors
    print(f"\n🔄 Generating production test vectors...")
    print(f"📁 Output directory: {PRODUCTION_VECTORS_DIR}")
    
    successful_generators = 0
    total_generators = len(PRODUCTION_GENERATORS)
    
    for generator in PRODUCTION_GENERATORS:
        if run_production_generator(generator, args.force):
            successful_generators += 1
    
    # Generate summary
    generate_production_summary()
    
    if successful_generators == total_generators:
        print("\n🎉 All production vectors generated successfully!")
        print("📁 Production vectors saved to: test/test_vectors/production/")
    else:
        print(f"\n⚠️  Only {successful_generators}/{total_generators} production vectors generated successfully.")
        print("Check the output above for errors.")


if __name__ == "__main__":
    main() 