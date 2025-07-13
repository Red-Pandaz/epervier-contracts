#!/usr/bin/env python3
"""
Test script using Alice's exact test vector data from registration_intent_vectors.json
This verifies our local contract deployment works with known good data.
"""

import json
from web3 import Web3
from eth_account import Account

# Alice's test vector data from registration_intent_vectors.json
ALICE_TEST_VECTOR = {
    "eth_address": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    "pq_fingerprint": "0x7B317F4D231CBc63dE7C6C690ef4Ba9C653437Fb",
    "base_pq_message": "07668882b5c3598c149b213b1c16ab1dd94b45bc4837b468e006b97caef5df92496e74656e7420746f207061697220455448204164647265737320f39fd6e51aad88f6f4ce6ab8827279cfffb922660000000000000000000000000000000000000000000000000000000000000000",
    "pq_signature": {
        "salt": "0c493b323b132e8cc3cf5aa3cc9d7733f7cbb35fa9486fd840ff4a72139d1192e35fd9fe12d4891a",
        "cs1": [
            "0x600240022001f2ebb2f812f742fdb2f5f00c00083015700012fa6012d007e",
            "0x2f6a2f252f49000f000700552fa3004400240031007b2f61009b2f3700110074",
            "0x2ef5000a002c2fa0000900a22ed200f5007f00d62fe72ee62fcd2fb42fd80129",
            "0x134004600ba2f7000802fe600642feb2ffc01392ffb00a22fb9001f00730082",
            "0x2f4a2fa02fc000742f6b008e00822fcf00d400fc2fd700452ee1002500762ee9",
            "0x2ef0006502512fba2f8b00aa008c2fc400862edf002f0003006f001800620030",
            "0x2ff32ff200422feb2f2801182f572faf2f8e2fff2fff00792fbb00582fbe2fa8",
            "0x2f6b2ff62f7d2fcc2fa32eed00d300862fc72f9200e0002b006f2fca01020031",
            "0xd2f572f54002b00772fb82f7e2fea0011007e2ffa2fc6003b0083006400ce",
            "0x2fad2fe02f62000b2f992f512ee82f99000800b5012a2ffa00242fb42fb42fb4",
            "0x422f6200492fef008a2ff701892f382feb01dd00c3003c2fb900502f742f99",
            "0x2fcb2f94000800a32fe62fc901392fb72f4f2f48004300ab003a00262fcf2ee3",
            "0x5d2ff7004b00442ebf2ff8001f00ac003a00f32fcd00092edb00fb00920003",
            "0x2f00003d00c700152efa005000952fdd001e005400c92f942e5c00dd2f200041",
            "0x2f9f001300b500e800a22fb100a72fde000d00732f8a2f772fdd005c000200b3",
            "0x642fd02ed4004d2f0a00a7000e009c2f7c2ff0011300ac2fb90092003c0023",
            "0x6500302ea12fa3008400282fef2f132fd6001002002f5000bb01192f732f86",
            "0x2fa6009e00f000372f44004c2fd62f82005d2efe004a006c003a2eae2fc00078",
            "0x42ebf000300132f902f842f402fb62fec2f82010b2fc800362fd02f672f23",
            "0x2e8e2f922ff1019a2f6f2fec2fb42f6b2f642f3e2f6e2fad0007003600f02f5f",
            "0xc62fd90004007d00562fd92e9100eb00e22fb12fb8005600082f472f342ed6",
            "0x2fde00062ef62efc007c2e5400ae2fd901362efd009501072f0200af00d100f9",
            "0x58008800a82fd6002b000b004e00a22f752f7800582f842f572fb42fe500cb",
            "0xa22fd200a22fef007a2f3d008400282ff52f3b2fe4009700252ff200290068",
            "0x192fe92f972ffc2e922fef00942fbb2f71000c2fa62f02005d2f5400e62f31",
            "0x1242f762fb52fc2002f2fc8005a005b00c22fed2f442ed100322ea500782fc2",
            "0x2f162fcd2fcd006b2f660135005200f52ff12fcf00070066009a2f0730000085",
            "0x30002f182f902f4f2f88008a00f72fa5005a0004017800750042008e2f6c2faa",
            "0x2feb00412fc600032fae2eac2f590031005d2fbe00b12fa5005e2fe42fcd2fa1",
            "0x37006d00ae00962f2201d42ff52f8d00192fee00fe00842ff02fbb007d2fd4",
            "0x2f882fec008a006400280196005b00892f332fec2f19003c2f312fff2fc72f4b",
            "0x7a00d02f1300052f700080005400282e952fea2f3500a02f382fd400032f23"
        ],
        "cs2": [
            "0x2f722f9400d700682fef2f4d002800152f432f6d0079001d2ead2f3d2faa0008",
            "0x2fe92f40003c00842faf2f42014a2eef003800e601162fa9014500ae2f192f1b",
            "0x2f442eca2ed82ef5004900b92f422fcb00312f472f5f2f6700012f152f7c00f7",
            "0x2fb82ed700002ef4000401810026017c008c00bd00b32f722fd70049015d2ec9",
            "0x9c2f830040009a2fcb016200852f9b003e000e0011008e2f6800412f71007b",
            "0x2e4f2ea52ff52f8f00862f2a2fde2f9d007f00652f432f3200822f8a2f6a2f3e",
            "0x2f2c00ab2fd300b72fb800cb007100382fcb2f872ed72f6000412fd6009b2f26",
            "0x1c2f842f0700672f942f16011f2fa72fa52f70004b013c00612fee00670056",
            "0x2f2400f42fc42f9d2f2801042fd5000c006800da2eea2fef2e542fed009c0010",
            "0x72fba001e00532fa92f6400172fdf2fb9003c01422fac2ea3003f004300ed",
            "0x162f4e00a501102f692fa52f9c2fe900052fd02fb50189006200202fc70088",
            "0x2fc9008b2f8c00610015015c000b0067005700d7001c2ed500090049002f2fba",
            "0x1070049005e00352f7a001e00d401330053004f004d2fa901642fa900910033",
            "0xef2e8600692f72005100432f61008b0064007a2f8f0063000600392f9c2fcf",
            "0x1f2fc02eef01892f752f392f8c00542fea2f80005d2ecf2ff22f8c002f2ecf",
            "0x2f4f2f73018a008b00112fad00182f302f760019004e2e592fdf2f8e2faf0064",
            "0xb82ed52f692f4e2ef72f342fb301162f1b2f1c2fab2fde00812fc62fba2ee5",
            "0x2fd62ff9006900482fe400ba00ad00512faf00ec2fc7005c2f682fbe00382ecd",
            "0x2f6f2fb02ef82fb700850045010b2f152ff02f230014003300c02efe2fb80163",
            "0x2ff901420058009a2f992e0a00842fdb2f5700a92f282f892ffe01a62faa0037",
            "0x1c00222fa52fd800f7009d00962dc7003d01332f9d2f1100282ef9008b2ff3",
            "0x292ff300a9009e2f5200f400132f24000d00b7006a00492f9a003700700002",
            "0x2900692fbc2fcf2f7a010000b3001a2f932f5d2ff22e942eca00100031002f",
            "0x1832f802fb22f1b009e00df2eb000692f872eff2f0c00be007a2f0d2f852faf",
            "0x2f762fc82f5d0011007b2ef52fd32f472fac002e2fe52f5500c12f08002d2fa8",
            "0x2f2d00f400050084003e00652fbc00cb00442ff500602f5e2ef52fc1005c00b6",
            "0x2fbe2ee3007b2fd500c9002c2ff4008800122f592ec201bc2f5200312f882fb4",
            "0x2fdd2fbd01a30086004201d100922ee6000b008200652fe100d22e6e2fae00b2",
            "0xea2efb003800342f922f9b01312f412fed2f192f032f5a2ef8012200280046",
            "0xe62f332fef2fe32fbf00bf2f0d01072ed50166002100ef0093004c00ff0076",
            "0x2fa00004010200b100240077009c00242eb3003a2f0300c101040021004f008c",
            "0x572ec900ad2f7400200070003e2fdb009f2f312f762fd42fcd2ffd2fd02f66"
        ],
        "hint": 7500
    },
    "eth_signature": {
        "v": 28,
        "r": "0x20226c145690b922be5520627d17e5afc41dc243fd780372afc602356b8854a5",
        "s": "0x1a9665e29b7354adc0462bd9654aca4755e0ab3f95b381d1a9e686478f085e47"
    },
    "eth_nonce": 0
}

# Local Anvil configuration
LOCAL_CONFIG = {
    "rpc_url": "http://localhost:8545",
    "chain_id": 31337,
    "contracts": {
        "registry": "0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6",
        "nft": "0x8A791620dd6260079BF849Dc5567aDC3F2FdC318",
        "epervier_verifier": "0x5FbDB2315678afecb367f032d93F642f64180aa3"
    }
}

# Alice's private key (first Anvil account)
ALICE_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

def test_registration():
    """Test PQ registration using Alice's exact test vector"""
    print("🦅 Testing PQ Registration with Alice's Test Vector")
    
    # Setup Web3
    w3 = Web3(Web3.HTTPProvider(LOCAL_CONFIG['rpc_url']))
    account = Account.from_key(ALICE_PRIVATE_KEY)
    
    print(f"✅ Alice's address: {account.address}")
    print(f"✅ ETH balance: {w3.from_wei(w3.eth.get_balance(account.address), 'ether')} ETH")
    
    # Convert test vector data to contract format
    salt_bytes = bytes.fromhex(ALICE_TEST_VECTOR['pq_signature']['salt'])
    
    # Convert cs1 and cs2 to uint256 arrays (32 elements each)
    cs1_uint256 = []
    cs2_uint256 = []
    
    for hex_val in ALICE_TEST_VECTOR['pq_signature']['cs1']:
        cs1_uint256.append(int(hex_val, 16))
    
    for hex_val in ALICE_TEST_VECTOR['pq_signature']['cs2']:
        cs2_uint256.append(int(hex_val, 16))
    
    hint = ALICE_TEST_VECTOR['pq_signature']['hint']
    base_pq_bytes = bytes.fromhex(ALICE_TEST_VECTOR['base_pq_message'])
    eth_nonce = ALICE_TEST_VECTOR['eth_nonce']
    
    # Extract signature components  
    v = ALICE_TEST_VECTOR['eth_signature']['v']
    r = bytes.fromhex(ALICE_TEST_VECTOR['eth_signature']['r'][2:])  # Remove 0x
    s = bytes.fromhex(ALICE_TEST_VECTOR['eth_signature']['s'][2:])  # Remove 0x
    
    print(f"✅ Salt: {len(salt_bytes)} bytes")
    print(f"✅ CS1 array: {len(cs1_uint256)} elements")
    print(f"✅ CS2 array: {len(cs2_uint256)} elements") 
    print(f"✅ Hint: {hint}")
    print(f"✅ Base PQ message: {len(base_pq_bytes)} bytes")
    print(f"✅ ETH signature: v={v}, r={len(r)} bytes, s={len(s)} bytes")
    
    # Contract ABI for submitRegistrationIntent
    registry_abi = [
        {
            "inputs": [
                {"name": "salt", "type": "bytes"},
                {"name": "cs1Array", "type": "uint256[]"},
                {"name": "cs2Array", "type": "uint256[]"},
                {"name": "hint", "type": "uint256"},
                {"name": "basePQMessage", "type": "bytes"},
                {"name": "ethNonce", "type": "uint256"},
                {"name": "v", "type": "uint8"},
                {"name": "r", "type": "bytes32"},
                {"name": "s", "type": "bytes32"}
            ],
            "name": "submitRegistrationIntent",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        }
    ]
    
    # Create contract instance
    registry = w3.eth.contract(
        address=LOCAL_CONFIG['contracts']['registry'],
        abi=registry_abi
    )
    
    # Submit registration intent
    print("🚀 Submitting registration intent...")
    
    try:
        tx_hash = registry.functions.submitRegistrationIntent(
            salt_bytes,
            cs1_uint256,
            cs2_uint256, 
            hint,
            base_pq_bytes,
            eth_nonce,
            v,
            r,
            s
        ).transact({
            'from': account.address,
            'gas': 5000000
        })
        
        print(f"✅ Transaction submitted: {tx_hash.hex()}")
        
        # Wait for transaction receipt
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        
        if receipt.status == 1:
            print("🎉 SUCCESS! Registration completed successfully!")
            print(f"✅ Gas used: {receipt.gasUsed:,}")
            print(f"✅ Block number: {receipt.blockNumber}")
        else:
            print("❌ Transaction failed")
            
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    test_registration() 