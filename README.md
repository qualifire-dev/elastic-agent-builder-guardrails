# Qualifire + Elastic Agent Builder Integration

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Qualifire](https://img.shields.io/badge/Qualifire-Official%20SDK-green.svg)](https://github.com/qualifire-dev/qualifire-python-sdk)

**Guaranteed AI safety validation for all Elastic Agent Builder responses using Qualifire's real-time guardrails.**

This integration provides a production-ready API proxy that ensures **no AI response can bypass safety validation** - critical for enterprise deployments in healthcare, finance, legal, and other regulated industries.

---

## 🎯 **Problem Solved**

**Without this integration:**
- AI responses can contain hallucinations, unsafe content, or PII
- Tool-based safety approaches can be bypassed
- No guarantee of safety validation coverage
- Enterprise compliance requirements not met

**With this integration:**
- ✅ **100% validation coverage** - every response is checked
- ✅ **Cannot be bypassed** - proxy intercepts at network level  
- ✅ **Production-ready** - enterprise deployment options
- ✅ **Comprehensive safety** - full Qualifire check suite

## 🏗️ **Architecture**

```
Your Application → Qualifire Proxy → Elastic Agent Builder → Qualifire SDK → Validated Response
```

The proxy transparently intercepts all Agent Builder API calls, validates responses through Qualifire's official SDK, and returns safe content with detailed validation metadata.

## 🔄 **Two Integration Approaches**

This repository provides **complementary integration options** for different use cases:

### **API Proxy (Guaranteed Validation)**
- ✅ **Cannot be bypassed** - Network-level interception
- ✅ **100% validation coverage** - Every response validated
- ✅ **Enterprise-grade** - Perfect for regulated industries
- 🎯 **Use when**: You need guaranteed safety with zero bypass possibility

### **Workflows Integration (Flexible Validation)** 
- ✅ **Agent Builder workflows** - Uses HTTP steps natively
- ✅ **Flexible validation** - Agents choose when to validate
- ✅ **Easy configuration** - Simple workflow definitions
- 🎯 **Use when**: You want optional, configurable validation

Both use the official Qualifire Python SDK and can serve different customer segments.

## ⚡ **Quick Start**

### 1. Install Dependencies
```bash
git clone https://github.com/your-username/qualifire-elastic-integration
cd qualifire-elastic-integration
pip install -r requirements.txt
```

### 2. Configure Environment
```bash
cp .env.template .env
# Edit .env with your API keys
```

### 3. Start Proxy
```bash
python proxy.py
```

### 4. Test Both Integration Approaches

**API Proxy Demo (Guaranteed Validation):**
```bash
python proxy.py    # Start the proxy server
python demo.py     # Test guaranteed validation
```

**Workflows Demo (Flexible Validation):**
```bash
python workflow_demo.py    # Test workflow-based validation
```

**That's it!** You can now see both integration approaches in action.

## 🛡️ **Safety Features**

### Comprehensive Validation Checks
- **🧠 Hallucination Detection** - Prevents factual inaccuracies
- **🛡️ Content Moderation** - Blocks harmful/inappropriate content  
- **🔒 PII Detection** - Protects personal information
- **⚡ Prompt Injection Prevention** - Prevents security exploits
- **📊 Tool Use Quality** - Validates function call quality
- **📋 Grounding Verification** - Ensures context-appropriate responses

### Built-in Safety Policies
- **Default**: Hallucinations + Content Moderation (80% threshold)
- **High-Stakes**: All checks enabled (90% threshold) - for healthcare/finance/legal
- **Public-Facing**: Content + PII + Toxicity focused (90% threshold)  
- **Research**: Lower thresholds, allows flagged responses for analysis

### Policy Selection
```bash
# Use high-stakes validation
curl -H "X-High-Risk: true" http://localhost:8000/api/agent_builder/converse

# Use public-facing validation
curl -H "X-Public-Facing: true" http://localhost:8000/api/agent_builder/converse

# Specify domain for automatic policy selection  
curl -H "X-Domain: healthcare" http://localhost:8000/api/agent_builder/converse
```

## 📊 **Response Format**

Every validated response includes comprehensive safety metadata:

```json
{
  "response": "The validated AI response",
  "qualifire_validation": {
    "validation_status": "passed",
    "policy_applied": "default",
    "overall_score": 95,
    "validation_time_ms": 15.3,
    "check_details": {
      "hallucinations": [{
        "name": "hallucination_check",
        "score": 100,
        "flagged": false,
        "reason": "Response is factually accurate"
      }]
    },
    "failed_checks": []
  }
}
```

## 🚀 **Production Deployment**

### Docker
```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["python", "proxy.py"]
```

### Kubernetes
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: qualifire-proxy
spec:
  replicas: 3
  selector:
    matchLabels:
      app: qualifire-proxy
  template:
    spec:
      containers:
      - name: proxy
        image: qualifire-proxy:latest
        ports:
        - containerPort: 8000
        env:
        - name: QUALIFIRE_API_KEY
          valueFrom:
            secretKeyRef:
              name: qualifire-secrets
              key: api-key
```

### Load Balancing
Deploy multiple proxy instances behind a load balancer for high availability and scale.

## 📈 **Performance**

- **Validation Latency**: 15-50ms (Qualifire's optimized models)
- **Proxy Overhead**: ~1-2ms  
- **Throughput**: Scales horizontally with multiple instances
- **Availability**: 99.9%+ with proper deployment

## 🔧 **API Endpoints**

### Validated Endpoints
- `POST /api/agent_builder/converse` - Chat with guaranteed validation

### Management Endpoints  
- `GET /health` - Proxy health check
- `GET /policies` - List available validation policies
- `GET /validate/test` - Test Qualifire SDK integration

### Pass-Through Endpoints
- All other Agent Builder APIs (`/agents`, `/tools`, etc.) work normally

## 🎯 **Use Cases**

### Healthcare
```python
# Automatically applies high-stakes policy
headers = {"X-Domain": "healthcare"}
response = requests.post(proxy_url, json=query, headers=headers)
```

### Customer Support
```python
# Uses public-facing policy with PII detection
headers = {"X-Public-Facing": "true"}  
response = requests.post(proxy_url, json=query, headers=headers)
```

### Financial Services
```python
# Applies comprehensive validation
headers = {"X-High-Risk": "true", "X-Domain": "finance"}
response = requests.post(proxy_url, json=query, headers=headers)
```

## 🛠️ **Configuration**

### Environment Variables
```env
# Required
QUALIFIRE_API_KEY=your_qualifire_api_key
KIBANA_URL=https://your-deployment.kb.region.aws.elastic.cloud  
ELASTIC_API_KEY=your_elastic_api_key

# Optional
QUALIFIRE_BASE_URL=https://api.qualifire.ai
DEBUG=true
```

### Custom Policies
Add custom validation policies by modifying `proxy.py`:

```python
self.policies["custom"] = ValidationPolicy(
    name="custom",
    confidence_threshold=0.85,
    hallucinations_check=True,
    content_moderation_check=True,
    pii_check=True,
    # Configure any Qualifire checks
)
```

## 📋 **Requirements**

- **Python**: 3.8+
- **Qualifire Account**: Get API key from [app.qualifire.ai](https://app.qualifire.ai)
- **Elastic Cloud**: Agent Builder enabled deployment  
- **Dependencies**: Listed in `requirements.txt`

## 🧪 **Testing**

```bash
# Run comprehensive demo
python demo.py

# Test specific policies
python -c "
import requests
response = requests.post('http://localhost:8000/api/agent_builder/converse',
    json={'input': 'Test query', 'agent_id': 'test'},
    headers={'X-High-Risk': 'true'}
)
print(response.json())
"
```

## 🤝 **Contributing**

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📚 **Resources**

- **Qualifire Documentation**: https://docs.qualifire.ai
- **Qualifire Dashboard**: https://app.qualifire.ai
- **Qualifire Python SDK**: https://github.com/qualifire-dev/qualifire-python-sdk
- **Elastic Agent Builder**: https://www.elastic.co/guide/en/elasticsearch/reference/current/agent-builder.html

## 🆘 **Support**

- **Issues**: Create an issue in this repository
- **Qualifire Support**: Contact support via [app.qualifire.ai](https://app.qualifire.ai)
- **Elastic Support**: Check Elastic documentation

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 **Acknowledgments**

- **Qualifire Team** for the excellent Python SDK and safety platform
- **Elastic Team** for Agent Builder and comprehensive API access
- **Community** for feedback and contributions

---

**⭐ If this integration helps your AI safety efforts, please star this repository!**

**🛡️ Result**: Every AI response from Elastic Agent Builder will be validated through Qualifire's comprehensive safety checks with detailed scoring and explanations.**
