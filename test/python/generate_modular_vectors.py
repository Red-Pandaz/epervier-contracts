#!/usr/bin/env python3
"""
Modular test vector generation script.

This script demonstrates how to use the new modular test vector generation system.
It provides a simple interface to generate comprehensive test vectors for PQRegistry.
"""

import sys
from pathlib import Path

# Add the vector_generators package to the path
sys.path.append(str(Path(__file__).parent / "vector_generators"))

from vector_generators.main_orchestrator import TestVectorOrchestrator


def main():
    """Main function to demonstrate modular vector generation."""
    print("PQRegistry Modular Test Vector Generator")
    print("=" * 50)
    
    # Initialize the orchestrator
    orchestrator = TestVectorOrchestrator()
    
    # Generate all vectors
    print("\nGenerating comprehensive test vectors...")
    vectors = orchestrator.generate_all_vectors()
    
    # Print summary
    orchestrator.print_summary(vectors)
    
    # Save vectors
    output_path = orchestrator.save_vectors(vectors)
    
    # Generate and save summary report
    report = orchestrator.generate_summary_report(vectors)
    report_path = output_path.parent / "generation_report.json"
    
    import json
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\nGeneration report saved to: {report_path}")
    print("\nTest vector generation completed successfully!")
    
    # Example of generating vectors for a specific function
    print("\n" + "=" * 50)
    print("Example: Generating registration vectors only...")
    
    registration_vectors = orchestrator.generate_function_vectors("registration")
    print(f"Generated {len(registration_vectors['registration'])} registration vector categories")
    
    # Save registration vectors separately
    reg_output_path = orchestrator.save_vectors(
        registration_vectors, 
        filename="registration_vectors_example.json"
    )
    print(f"Saved registration vectors to: {reg_output_path}")


if __name__ == "__main__":
    main() 