#!/bin/bash
# Quick Start Script for Rogue Security + Elastic Agent Builder Integration

echo "🚀 Rogue Security + Elastic Agent Builder Setup"
echo "================================================"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3.8+"
    exit 1
fi

echo "✅ Python found: $(python3 --version)"

# Install dependencies
echo "📦 Installing dependencies..."
pip install -r requirements.txt

# Check for .env file
if [ ! -f .env ]; then
    echo "📝 Creating .env file from template..."
    cp .env.template .env
    echo "⚠️  Please edit .env with your actual API keys:"
    echo "   - ROGUE_API_KEY"
    echo "   - KIBANA_URL"
    echo "   - ELASTIC_API_KEY"
    echo ""
    echo "Then run: python proxy.py"
else
    echo "✅ .env file exists"
    echo "🚀 Starting proxy server..."
    python proxy.py
fi
