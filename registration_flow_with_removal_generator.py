import json
from pathlib import Path

def main():
    print("Generating registration flow with removal test vectors in passing format...")
    try:
        vectors = generate_registration_flow_with_removal_vectors()
        formatted_vectors = []
        for scenario in vectors:
            for step in scenario["steps"]:
                # Only include steps that have all required fields
                if all(k in step for k in ["base_pq_message", "pq_signature", "eth_message", "eth_signature", "eth_nonce"]):
                    formatted_vectors.append({
                        "actor": scenario.get("actor", ""),
                        "eth_address": scenario.get("eth_address", ""),
                        "pq_fingerprint": scenario.get("pq_fingerprint", ""),
                        "base_pq_message": step["base_pq_message"],
                        "pq_signature": step["pq_signature"],
                        "eth_message": step["eth_message"],
                        "eth_signature": {
                            "v": step["eth_signature"]["v"],
                            "r": int(step["eth_signature"]["r"]),
                            "s": int(step["eth_signature"]["s"])
                        },
                        "eth_nonce": step["eth_nonce"]
                    })
        output = {"registration_intent": formatted_vectors}
        output_path = Path("../../test/test_vectors/advanced/registration_flow_with_removal_vectors.json")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(output, f, indent=2)
        print(f"✅ Generated {len(formatted_vectors)} registration intent vectors in passing format!")
        print(f"📁 Saved to: {output_path}")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main() 