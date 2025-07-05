#!/usr/bin/env python3
"""
Comprehensive test vector generator for PQRegistry

This script generates all test vectors needed for the PQRegistry contract tests.
It runs all individual vector generators in the correct order to ensure dependencies
are satisfied.

Usage:
    python3 generate_all_vectors.py [--force] [--actors-only]

Options:
    --force: Regenerate all vectors even if they exist
    --actors-only: Only generate vectors for a subset of actors (for testing)
"""

import json
import subprocess
import sys
import shutil
from pathlib import Path
from typing import List, Dict, Any
import argparse

# Get the project root directory
PROJECT_ROOT = Path(__file__).resolve().parents[3]  # epervier-registry
VECTOR_GENERATORS_DIR = PROJECT_ROOT / "test/python/vector_generators"
TEST_VECTORS_DIR = PROJECT_ROOT / "test/test_vectors"
# Use the virtual environment Python for running generators
VENV_PYTHON = PROJECT_ROOT / "ETHFALCON/python-ref/myenv/bin/python3"

# Vector generators for main test vectors
VECTOR_GENERATORS = [
    {
        "name": "Registration Intent Vectors",
        "script": "register/registration_intent_generator.py",
        "output": "register/registration_intent_vectors.json",
        "description": "Test vectors for submitRegistrationIntent function"
    },
    {
        "name": "Registration Confirmation Vectors",
        "script": "register/registration_confirmation_generator.py",
        "output": "register/registration_confirmation_vectors.json",
        "description": "Test vectors for confirmRegistration function"
    },
    {
        "name": "Registration Removal Vectors",
        "script": "register/registration_intent_eth_removal_generator.py",
        "output": "register/registration_removal_vectors.json",
        "description": "Test vectors for removeRegistrationIntentByETH function"
    },
    {
        "name": "Change ETH Address Intent Vectors",
        "script": "change_eth/change_eth_address_intent_generator.py",
        "output": "change_eth/change_eth_address_intent_vectors.json",
        "description": "Test vectors for submitChangeETHAddressIntent function"
    },
    {
        "name": "Change ETH Address Confirmation Vectors",
        "script": "change_eth/change_eth_address_confirmation_generator.py",
        "output": "change_eth/change_eth_address_confirmation_vectors.json",
        "description": "Test vectors for confirmChangeETHAddress function"
    },
    {
        "name": "Change ETH Address Removal Vectors",
        "script": "change_eth/change_eth_address_intent_eth_removal_generator.py",
        "output": "change_eth/change_eth_address_removal_vectors.json",
        "description": "Test vectors for removeChangeETHAddressIntentByETH function"
    },
    {
        "name": "Unregistration Intent Vectors",
        "script": "unregister/unregistration_intent_generator.py",
        "output": "unregister/unregistration_intent_vectors.json",
        "description": "Test vectors for submitUnregistrationIntent function"
    },
    {
        "name": "Unregistration Confirmation Vectors",
        "script": "unregister/unregistration_confirmation_generator.py",
        "output": "unregister/unregistration_confirmation_vectors.json",
        "description": "Test vectors for confirmUnregistration function"
    },
    {
        "name": "Unregistration Removal Vectors",
        "script": "unregister/unregistration_flow_with_revocation_generator.py",
        "output": "unregister/unregistration_removal_vectors.json",
        "description": "Test vectors for removeUnregistrationIntentByETH function"
    },
    {
        "name": "Advanced Testing Vectors",
        "script": "advanced/consolidated_advanced_vector_generator.py",
        "output": "advanced/advanced_testing_vectors.json",
        "description": "Advanced test vectors for complex scenarios"
    }
]


def load_actors_config() -> Dict[str, Any]:
    """Load the actors configuration file."""
    actors_config_path = PROJECT_ROOT / "test/test_keys/actors_config.json"
    with open(actors_config_path, "r") as f:
        return json.load(f)["actors"]


def check_dependencies() -> bool:
    """Check if all required dependencies are available."""
    print("Checking dependencies...")
    
    # Check if actors config exists
    actors_config_path = PROJECT_ROOT / "test/test_keys/actors_config.json"
    if not actors_config_path.exists():
        print(f"❌ Actors config not found: {actors_config_path}")
        return False
    print(f"✅ Actors config found: {actors_config_path}")
    
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
    
    # Check if test vectors directory exists
    if not TEST_VECTORS_DIR.exists():
        print(f"Creating test vectors directory: {TEST_VECTORS_DIR}")
        TEST_VECTORS_DIR.mkdir(parents=True, exist_ok=True)
    else:
        print(f"✅ Test vectors directory exists: {TEST_VECTORS_DIR}")
    
    return True


def run_generator(generator: Dict[str, str], force: bool = False, actors_only: bool = False) -> bool:
    """Run a single vector generator."""
    script_path = VECTOR_GENERATORS_DIR / generator["script"]
    
    # Handle different output types
    if generator["output"].endswith("/") or generator["output"] == "advanced":
        # Output is a directory
        output_path = TEST_VECTORS_DIR / generator["output"]
        output_exists = output_path.exists() and any(output_path.iterdir())
    else:
        # Output is a specific file
        output_path = TEST_VECTORS_DIR / generator["output"]
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
        if actors_only:
            cmd.extend(["--actors-only"])
        
        print(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=VECTOR_GENERATORS_DIR)
        
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


def generate_summary() -> None:
    """Generate a summary of all created vectors."""
    print(f"\n{'='*60}")
    print("📊 GENERATION SUMMARY")
    print(f"{'='*60}")
    
    total_generators = len(VECTOR_GENERATORS)
    successful_generators = 0
    
    for generator in VECTOR_GENERATORS:
        output_path = TEST_VECTORS_DIR / generator["output"]
        
        # Handle different output types
        if generator["output"].endswith("/") or generator["output"] == "advanced":
            # Output is a directory
            if output_path.exists() and any(output_path.iterdir()):
                # Count files in directory
                file_count = len(list(output_path.glob("*.json")))
                total_size = sum(f.stat().st_size for f in output_path.glob("*.json"))
                size_kb = total_size / 1024
                print(f"✅ {generator['name']:<30} | {file_count:>2} files | {size_kb:>6.1f} KB")
                successful_generators += 1
            else:
                print(f"❌ {generator['name']:<30} | Not generated")
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
                        print(f"✅ {generator['name']:<30} | {vector_count:>2} vectors | {size_kb:>6.1f} KB")
                        successful_generators += 1
                except Exception as e:
                    print(f"❌ {generator['name']:<30} | Error reading: {e}")
            else:
                print(f"❌ {generator['name']:<30} | Not generated")
    
    print(f"\n📈 Success Rate: {successful_generators}/{total_generators} ({successful_generators/total_generators*100:.1f}%)")
    
    if successful_generators == total_generators:
        print("🎉 All vectors generated successfully!")
    else:
        print("⚠️  Some vectors failed to generate. Check the output above.")


def main():
    """Main function to generate all test vectors."""
    parser = argparse.ArgumentParser(description="Generate all test vectors for PQRegistry")
    parser.add_argument("--force", action="store_true", help="Regenerate all vectors even if they exist")
    parser.add_argument("--actors-only", action="store_true", help="Only generate vectors for a subset of actors (for testing)")
    parser.add_argument("--check-only", action="store_true", help="Only check dependencies without generating vectors")
    parser.add_argument("--cleanup", action="store_true", help="Delete all existing test vectors before generating new ones")
    
    args = parser.parse_args()
    
    print("🚀 PQRegistry Test Vector Generator")
    print("=" * 50)
    
    # Check dependencies
    if not check_dependencies():
        print("❌ Dependencies check failed. Please fix the issues above.")
        sys.exit(1)
    
    if args.check_only:
        print("✅ Dependencies check passed!")
        return
    
    # Cleanup existing test vectors if requested
    if args.cleanup:
        print("\n🧹 Cleaning up existing test vectors...")
        if TEST_VECTORS_DIR.exists():
            print(f"🗑️  Deleting test vectors directory: {TEST_VECTORS_DIR}")
            shutil.rmtree(TEST_VECTORS_DIR)
            print("✅ Test vectors directory deleted")
        else:
            print("ℹ️  Test vectors directory does not exist, nothing to delete")
        
        # Recreate the test vectors directory
        print(f"📁 Creating test vectors directory: {TEST_VECTORS_DIR}")
        TEST_VECTORS_DIR.mkdir(parents=True, exist_ok=True)
        print("✅ Test vectors directory created")
    
    # Load actors config to show what we're working with
    actors = load_actors_config()
    print(f"📋 Found {len(actors)} actors in config:")
    for name, actor in actors.items():
        print(f"   • {name.capitalize()}: {actor['eth_address']}")
    
    # Generate all vectors
    print(f"\n🔄 Starting generation of {len(VECTOR_GENERATORS)} vector types...")
    
    failed_generators = []
    for generator in VECTOR_GENERATORS:
        success = run_generator(generator, force=args.force, actors_only=args.actors_only)
        if not success:
            failed_generators.append(generator["name"])
    
    # Generate summary
    generate_summary()
    
    # Exit with appropriate code
    if failed_generators:
        print(f"\n❌ Failed generators: {', '.join(failed_generators)}")
        sys.exit(1)
    else:
        print(f"\n🎉 All vectors generated successfully!")
        print(f"📁 Output directory: {TEST_VECTORS_DIR}")


if __name__ == "__main__":
    main()
