import subprocess
import os
import shutil

# Paths
cli_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../ETHFALCON/python-ref/sign_cli.py'))
python_ref_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../ETHFALCON/python-ref'))
venv_python = os.path.join(python_ref_dir, 'myenv', 'bin', 'python')
key_path = os.path.join(python_ref_dir, 'private_key.pem')  # CLI generates keys in python-ref directory
pubkey_path = os.path.join(python_ref_dir, 'public_key.pem')  # CLI generates keys in python-ref directory
sig1_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'sig1'))
sig2_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'sig2'))

# Contract and RPC configuration
contract_address = "0x5ab1d6db02f48bad63cbef5d51c534A76aEB824B"  # EPERVIER contract on Optimism Sepolia
rpc_url = "https://sepolia.optimism.io"

msg1 = "first message"
msg2 = "second message"
msg3 = "third message"
msg4 = "fourth message"

# 1. Generate keypair
def run_cli(args):
    # Change to the python-ref directory before running the command
    original_cwd = os.getcwd()
    os.chdir(python_ref_dir)
    try:
        result = subprocess.run(args, capture_output=True, text=True)
        if result.returncode != 0:
            print("Error:", result.stderr)
            exit(1)
        return result.stdout.strip()
    finally:
        os.chdir(original_cwd)

def run_cli_with_logging(args, description):
    # Change to the python-ref directory before running the command
    original_cwd = os.getcwd()
    os.chdir(python_ref_dir)
    try:
        print(f"\n--- {description} ---")
        print(f"Command: {' '.join(args)}")
        result = subprocess.run(args, capture_output=True, text=True)
        print(f"Return code: {result.returncode}")
        print(f"STDOUT: {repr(result.stdout)}")
        print(f"STDERR: {repr(result.stderr)}")
        if result.returncode != 0:
            print("Error: Command failed with return code", result.returncode)
            print("STDERR:", result.stderr)
            # Don't exit, just return the stderr as the result
            return result.stderr.strip()
        return result.stdout.strip()
    finally:
        os.chdir(original_cwd)

print("Generating keypair...")
run_cli([venv_python, "sign_cli.py", "genkeys", "--version", "epervier"])

# 2. Sign first message
print("Signing first message...")
run_cli([venv_python, "sign_cli.py", "sign", "--privkey", key_path, "--data", msg1.encode().hex()])
# Copy the signature to our test directory
shutil.copy(os.path.join(python_ref_dir, 'sig'), sig1_path)

# 3. Sign second message
print("Signing second message...")
run_cli([venv_python, "sign_cli.py", "sign", "--privkey", key_path, "--data", msg2.encode().hex()])
# Copy the signature to our test directory
shutil.copy(os.path.join(python_ref_dir, 'sig'), sig2_path)

# Test a simple recovery first to see what happens
print("\n=== Testing single recovery first ===")
test_result = run_cli_with_logging([venv_python, "sign_cli.py", "recoveronchain", "--signature", sig1_path, "--data", msg1.encode().hex(), "--pubkey", pubkey_path, "--contractaddress", contract_address, "--rpc", rpc_url], "Single recovery test")
print("Test result:", repr(test_result))

# 4. Recover prints for all 8 scenarios
print("\n=== Testing 8 recovery scenarios ===")

print1 = run_cli_with_logging([venv_python, "sign_cli.py", "recoveronchain", "--signature", sig1_path, "--data", msg1.encode().hex(), "--pubkey", pubkey_path, "--contractaddress", contract_address, "--rpc", rpc_url], "Recovery 1: sig1 + msg1 (correct match)")

print2 = run_cli_with_logging([venv_python, "sign_cli.py", "recoveronchain", "--signature", sig2_path, "--data", msg2.encode().hex(), "--pubkey", pubkey_path, "--contractaddress", contract_address, "--rpc", rpc_url], "Recovery 2: sig2 + msg2 (correct match)")

print3 = run_cli_with_logging([venv_python, "sign_cli.py", "recoveronchain", "--signature", sig1_path, "--data", msg2.encode().hex(), "--pubkey", pubkey_path, "--contractaddress", contract_address, "--rpc", rpc_url], "Recovery 3: sig1 + msg2 (mismatched)")

print4 = run_cli_with_logging([venv_python, "sign_cli.py", "recoveronchain", "--signature", sig2_path, "--data", msg1.encode().hex(), "--pubkey", pubkey_path, "--contractaddress", contract_address, "--rpc", rpc_url], "Recovery 4: sig2 + msg1 (mismatched)")

print5 = run_cli_with_logging([venv_python, "sign_cli.py", "recoveronchain", "--signature", sig1_path, "--data", msg3.encode().hex(), "--pubkey", pubkey_path, "--contractaddress", contract_address, "--rpc", rpc_url], "Recovery 5: sig1 + msg3")

print6 = run_cli_with_logging([venv_python, "sign_cli.py", "recoveronchain", "--signature", sig1_path, "--data", msg4.encode().hex(), "--pubkey", pubkey_path, "--contractaddress", contract_address, "--rpc", rpc_url], "Recovery 6: sig1 + msg4")

print7 = run_cli_with_logging([venv_python, "sign_cli.py", "recoveronchain", "--signature", sig2_path, "--data", msg3.encode().hex(), "--pubkey", pubkey_path, "--contractaddress", contract_address, "--rpc", rpc_url], "Recovery 7: sig2 + msg3")

print8 = run_cli_with_logging([venv_python, "sign_cli.py", "recoveronchain", "--signature", sig2_path, "--data", msg4.encode().hex(), "--pubkey", pubkey_path, "--contractaddress", contract_address, "--rpc", rpc_url], "Recovery 8: sig2 + msg4")

print("\n=== Results ===")
print("Recovered print 1 (sig1 + msg1):", print1)
print("Recovered print 2 (sig2 + msg2):", print2)
print("Recovered print 3 (sig1 + msg2):", print3)
print("Recovered print 4 (sig2 + msg1):", print4)
print("Recovered print 5 (sig1 + msg3):", print5)
print("Recovered print 6 (sig1 + msg4):", print6)
print("Recovered print 7 (sig2 + msg3):", print7)
print("Recovered print 8 (sig2 + msg4):", print8)

print("\n=== Raw Recovery Values ===")
print("print1:", repr(print1))
print("print2:", repr(print2))
print("print3:", repr(print3))
print("print4:", repr(print4))
print("print5:", repr(print5))
print("print6:", repr(print6))
print("print7:", repr(print7))
print("print8:", repr(print8))

print("\n=== Analysis ===")
if print1 == print2:
    print("✅ PASS: Same key, different messages, same recovery (print1 == print2)")
else:
    print("❌ FAIL: Same key, different messages, different recovery (print1 != print2)")

if print3 != print4:
    print("✅ PASS: Mismatched signatures/messages give different recoveries (print3 != print4)")
else:
    print("❌ FAIL: Mismatched signatures/messages give same recovery (print3 == print4)")

if print1 != print3:
    print("✅ PASS: Correct vs mismatched signature give different recoveries (print1 != print3)")
else:
    print("❌ FAIL: Correct vs mismatched signature give same recovery (print1 == print3)")

if print2 != print4:
    print("✅ PASS: Correct vs mismatched signature give different recoveries (print2 != print4)")
else:
    print("❌ FAIL: Correct vs mismatched signature give same recovery (print2 == print4)")

# Test that all mismatched scenarios give different results
mismatched_prints = [print3, print4, print5, print6, print7, print8]
correct_prints = [print1, print2]

print("\n=== Additional Analysis ===")
all_different = True
for i, p1 in enumerate(mismatched_prints):
    for j, p2 in enumerate(mismatched_prints[i+1:], i+1):
        if p1 == p2:
            print(f"❌ FAIL: Mismatched scenarios {i+3} and {j+3} give same recovery")
            all_different = False

if all_different:
    print("✅ PASS: All mismatched scenarios give different recoveries")

# Check that correct matches are different from mismatched
for i, correct in enumerate(correct_prints):
    for j, mismatched in enumerate(mismatched_prints):
        if correct == mismatched:
            print(f"❌ FAIL: Correct scenario {i+1} matches mismatched scenario {j+3}")
        else:
            print(f"✅ PASS: Correct scenario {i+1} differs from mismatched scenario {j+3}") 