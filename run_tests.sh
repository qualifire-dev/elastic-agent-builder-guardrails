#!/bin/bash
# Integration Test Runner for Rogue Security + Elastic Agent Builder
# ===================================================================

set -e

echo "🧪 Rogue Security + Elastic Agent Builder Integration Tests"
echo "============================================================"
echo ""

# Check for .env file
if [ ! -f .env ]; then
    echo "⚠️  No .env file found. Creating from template..."
    cp env-template.txt .env
    echo "❌ Please edit .env with your actual API keys and run again."
    exit 1
fi

# Load environment variables
source .env 2>/dev/null || export $(cat .env | grep -v '^#' | xargs)

# Verify required variables
echo "📋 Configuration Check:"
echo ""

if [ -z "$ROGUE_API_KEY" ]; then
    echo "  ❌ ROGUE_API_KEY: NOT SET"
    MISSING_VARS=1
else
    echo "  ✅ ROGUE_API_KEY: Set (${ROGUE_API_KEY:0:10}...)"
fi

if [ -z "$KIBANA_URL" ]; then
    echo "  ❌ KIBANA_URL: NOT SET"
    MISSING_VARS=1
else
    echo "  ✅ KIBANA_URL: $KIBANA_URL"
fi

if [ -z "$ELASTIC_API_KEY" ]; then
    echo "  ❌ ELASTIC_API_KEY: NOT SET"
    MISSING_VARS=1
else
    echo "  ✅ ELASTIC_API_KEY: Set (${ELASTIC_API_KEY:0:10}...)"
fi

ROGUE_API_URL=${ROGUE_API_URL:-https://api.rogue.security}
echo "  ℹ️  ROGUE_API_URL: $ROGUE_API_URL"

PROXY_URL=${PROXY_URL:-http://localhost:8000}
echo "  ℹ️  PROXY_URL: $PROXY_URL"

echo ""

if [ -n "$MISSING_VARS" ]; then
    echo "❌ Missing required environment variables. Please update .env"
    exit 1
fi

# Check if proxy is running
echo "🔍 Checking proxy status..."
if curl -s "$PROXY_URL/health" > /dev/null 2>&1; then
    echo "  ✅ Proxy is running at $PROXY_URL"
    PROXY_RUNNING=1
else
    echo "  ⚠️  Proxy is not running at $PROXY_URL"
    echo "     Some tests will be skipped."
    echo "     Start proxy with: python proxy.py"
    PROXY_RUNNING=0
fi

echo ""

# Parse arguments
TEST_TYPE="${1:-all}"

echo "🚀 Running tests..."
echo ""

case $TEST_TYPE in
    rogue)
        echo "Running Rogue Security API tests only..."
        pytest test_integration.py -v -k "TestRogueSecurityAPI" --tb=short
        ;;
    elastic)
        echo "Running Elastic Agent Builder tests only..."
        pytest test_integration.py -v -k "TestElasticAgentBuilderAPI" --tb=short
        ;;
    proxy)
        echo "Running Proxy integration tests only..."
        pytest test_integration.py -v -k "TestProxyIntegration" --tb=short
        ;;
    e2e)
        echo "Running End-to-End tests only..."
        pytest test_integration.py -v -k "TestEndToEnd" --tb=short
        ;;
    perf)
        echo "Running Performance tests only..."
        pytest test_integration.py -v -k "TestPerformance" --tb=short
        ;;
    all)
        echo "Running all tests..."
        pytest test_integration.py -v --tb=short
        ;;
    *)
        echo "Usage: $0 [rogue|elastic|proxy|e2e|perf|all]"
        echo ""
        echo "Test suites:"
        echo "  rogue   - Test Rogue Security API directly"
        echo "  elastic - Test Elastic Agent Builder API directly"
        echo "  proxy   - Test the proxy integration"
        echo "  e2e     - Run end-to-end tests"
        echo "  perf    - Run performance benchmarks"
        echo "  all     - Run all tests (default)"
        exit 1
        ;;
esac

echo ""
echo "✅ Tests completed!"
