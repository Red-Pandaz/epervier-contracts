# 🦅 Epervier PQ Playground

Welcome to the interactive Post-Quantum Cryptography playground! Experience the future of quantum-resistant blockchain technology.

## 🚀 Quick Start

1. **Install dependencies:**
   ```bash
   pip install -r scripts/requirements.txt
   ```

2. **Clone and setup ETHFALCON (required for PQ operations):**
   ```bash
   git clone https://github.com/zknox/ETHFALCON.git
   cd ETHFALCON/python-ref
   make install
   cd ../..
   ```

3. **Run the playground:**
   ```bash
   python scripts/pq_user_playground.py
   ```

## 🎮 What You Can Do

- **🔧 Setup Environment** - Generate or import your Ethereum private key
- **🗝️ Generate PQ Keys** - Create your post-quantum Epervier key pair
- **📝 2-Step Registration** - Link your PQ identity to your Ethereum address (auto-mints NFT on-chain!)
- **🔄 Transfer NFTs** - Move tokens using post-quantum signatures
- **📊 Check Status** - View your PQ setup and assets

## 🛡️ Security Notes

- ⚠️ This is for **testing and educational purposes** only
- 🔒 Your private keys are stored locally in `user_data/.env`
- 🧪 Uses OP Sepolia testnet (no real value)
- 🚨 Never use generated test keys with real funds
- 💰 You need OP Sepolia ETH for gas fees (get from [bridge](https://superbridge.app/) or faucets)

## 📁 Generated Files

- `user_data/.env` - Your environment variables and keys
- `user_data/user_config.json` - Your playground progress
- `ETHFALCON/private_key.pem` - Your PQ private key
- `ETHFALCON/public_key.pem` - Your PQ public key

## 🆘 Need Help?

If you encounter issues:
1. Make sure ETHFALCON is cloned in the project root
2. Ensure ETHFALCON virtual environment is set up (`ETHFALCON/python-ref/myenv/`)
3. Check that you have all Python dependencies installed
4. Ensure you're using OP Sepolia testnet
5. Use the "Clean Setup" option to start fresh

**Common Issues:**
- `ModuleNotFoundError`: ETHFALCON virtual environment not activated
- `FileNotFoundError`: ETHFALCON not cloned or in wrong location
- `Permission denied`: Make sure the script is executable (`chmod +x`)

Happy quantum-resistant crypto exploring! 🌌 