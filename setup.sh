#!/bin/bash

# Epervier Registry Setup Script
# This script initializes all dependencies including ETHFALCON CLI

set -e

echo "🚀 Setting up Epervier Registry..."

# Initialize git submodules
echo "📦 Initializing git submodules..."
git submodule update --init --recursive

# Install Forge dependencies
echo "🔧 Installing Forge dependencies..."
forge install

# Set up ETHFALCON Python environment
echo "🐍 Setting up ETHFALCON Python environment..."
cd ETHFALCON/python-ref

# Check if virtual environment exists
if [ ! -d "myenv" ]; then
    echo "📋 Creating Python virtual environment..."
    python3 -m venv myenv
fi

# Activate virtual environment
echo "🔄 Activating virtual environment..."
source myenv/bin/activate

# Install Python dependencies
echo "📚 Installing Python dependencies..."
pip install -r requirements.txt

# Return to project root
cd ../..

echo "✅ Setup complete!"
echo ""
echo "📋 Next steps:"
echo "1. Run tests: forge test"
echo "2. Set up environment: source script/setup_env.sh"
echo "3. Deploy locally: forge script script/DeployLocalEpervier.s.sol --broadcast"
echo ""
echo "🔑 To use ETHFALCON CLI:"
echo "cd ETHFALCON/python-ref"
echo "source myenv/bin/activate"
echo "python sign_cli.py --help" 