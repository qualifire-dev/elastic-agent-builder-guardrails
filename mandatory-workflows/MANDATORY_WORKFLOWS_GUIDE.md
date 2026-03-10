# Mandatory Workflows Guide

## Rogue Security + Elastic Agent Builder

This guide explains how to implement **mandatory validation workflows** that ensure all AI agent interactions are validated through Rogue Security's guardrails before reaching users.

### Workflow Format

These workflows use the simplified Elastic Workflows YAML format:
- **No version field required** - simple, clean structure
- **`type: kibana.request`** - native Kibana API calls
- **Condition syntax**: `"steps.name.output.body.data.field: value"`
- **Single-line JSON body** - compact HTTP request bodies

---

## Table of Contents

1. [Gatekeeper vs Monitoring Pattern](#gatekeeper-vs-monitoring-pattern)
2. [Architecture](#architecture)
3. [Workflow Types](#workflow-types)
4. [Setup Instructions](#setup-instructions)
5. [Policy Configuration](#policy-configuration)
6. [Comparison: Workflows vs API Proxy](#comparison-workflows-vs-api-proxy)
7. [Troubleshooting](#troubleshooting)
8. [Best Practices](#best-practices)

---

## Gatekeeper vs Monitoring Pattern

### The Problem with Monitoring-Only Approaches

Traditional AI safety monitoring works like this:

```
User Input → Agent → Response to User → Safety Check (async)
                                              ↓
                                        Log violations
```

**Issues:**
- Unsafe content reaches users BEFORE validation
- No ability to block harmful responses in real-time
- Violations are detected after the fact
- Compliance gaps for regulated industries

### The Gatekeeper Pattern (Mandatory Validation)

Our mandatory workflows implement a **gatekeeper pattern**:

```
User Input → Input Validation → [BLOCK] or [PROCEED]
                                      ↓
                                    Agent
                                      ↓
            Output Validation → [BLOCK] or [DELIVER]
                                      ↓
                              Safe Response to User
```

**Benefits:**
- Unsafe inputs NEVER reach the agent
- Unsafe outputs NEVER reach users
- Real-time blocking with safe fallbacks
- Complete audit trail
- Compliance-ready for regulated industries

---

## Architecture

### Full Pipeline Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     MANDATORY VALIDATION PIPELINE                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   User Input                                                     │
│       │                                                          │
│       ▼                                                          │
│   ┌─────────────────────────────────────────┐                   │
│   │        INPUT VALIDATION GATE            │                   │
│   │   • Prompt injection detection          │                   │
│   │   • Content moderation                  │                   │
│   │   • Policy target: "input"              │                   │
│   └─────────────────┬───────────────────────┘                   │
│                     │                                            │
│         ┌───────────┴───────────┐                               │
│         │                       │                                │
│    [PASS]                   [FAIL]                              │
│         │                       │                                │
│         ▼                       ▼                                │
│   ┌─────────────┐        ┌─────────────────┐                    │
│   │   AGENT     │        │ BLOCK + SAFE    │                    │
│   │  EXECUTION  │        │    RESPONSE     │                    │
│   └──────┬──────┘        └─────────────────┘                    │
│          │                                                       │
│          ▼                                                       │
│   ┌─────────────────────────────────────────┐                   │
│   │       OUTPUT VALIDATION GATE            │                   │
│   │   • Hallucination detection             │                   │
│   │   • Content moderation                  │                   │
│   │   • PII detection                       │                   │
│   │   • Custom assertions                   │                   │
│   └─────────────────┬───────────────────────┘                   │
│                     │                                            │
│         ┌───────────┴───────────┐                               │
│         │                       │                                │
│    [PASS]                   [FAIL]                              │
│         │                       │                                │
│         ▼                       ▼                                │
│   ┌─────────────┐        ┌─────────────────┐                    │
│   │  DELIVER    │        │ BLOCK + SAFE    │                    │
│   │  RESPONSE   │        │    FALLBACK     │                    │
│   └─────────────┘        └─────────────────┘                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **User Input** arrives at the workflow
2. **Input Validation** checks for malicious content
3. If blocked → Return safe message, agent never executes
4. If passed → **Agent Execution** with validated input
5. **Output Validation** checks agent response
6. If blocked → Return safe fallback, original response discarded
7. If passed → **Deliver** validated response to user
8. **Logging** at every step for audit trail

---

## Workflow Types

### 1. Input Gating Workflow
**File:** `input-gating-workflow.yml`

Validates user input BEFORE agent execution:
- Prompt injection detection
- Content moderation
- Malicious request blocking

```yaml
name: rogue-input-gating
description: Validates input with Rogue API before passing to agent
enabled: true

triggers:
  - type: manual

inputs:
  - name: user_input
    type: string
  - name: agent_id
    type: string
  - name: session_id
    type: string

steps:
  - name: call_rogue
    type: http
    with:
      url: "https://api.rogue.security/api/v1/evaluation/evaluate"
      method: POST
      headers:
        X-Rogue-API-Key: "{{ secrets.rogue_api_key }}"
        Content-Type: "application/json"
      body: '{"messages":[{"role":"user","content":"{{ inputs.user_input }}"}],"prompt_injections":true,"content_moderation_check":true,"policy_target":"input"}'

  - name: check_safety
    type: if
    condition: "steps.call_rogue.output.body.data.status: success"
    steps:
      - name: call_agent
        type: kibana.request
        with:
          method: POST
          path: /api/agent_builder/converse
          body:
            input: "{{ inputs.user_input }}"
            agent_id: "{{ inputs.agent_id }}"

      - name: return_response
        type: return
        with:
          status: "allowed"
          response: "{{ steps.call_agent.output.response.message }}"

    else:
      - name: return_blocked
        type: return
        with:
          status: "blocked"
          response: "I cannot process this request due to safety policies."
```

### 2. Output Validation Workflow
**File:** `output-validation-workflow.yml`

Validates agent responses BEFORE delivery:
- Hallucination detection
- Content moderation
- PII detection
- Grounding verification

```yaml
# Key configuration
hallucinations_check: true
content_moderation_check: true
pii_check: true
grounding_check: true
```

### 3. Full Pipeline Workflow
**File:** `full-pipeline-workflow.yml`

Complete mandatory validation with both gates:
- Input validation gate
- Agent execution (only if input passes)
- Output validation gate
- Domain-based policy selection
- Comprehensive audit logging

---

## Setup Instructions

### Prerequisites

1. **Elastic Cloud** with Agent Builder enabled
2. **Rogue Security** account with API key
3. **Elasticsearch** for logging

### Step 1: Configure Secrets

Set up secrets in your Elastic environment:

```yaml
# In Kibana Console or via API
PUT _security/secret/rogue_api_key
{
  "value": "rsk_your_actual_api_key"
}

PUT _security/secret/elastic_api_key
{
  "value": "your_elastic_api_key"
}
```

### Step 2: Create Log Indices

```json
PUT rogue-validation-logs
{
  "mappings": {
    "properties": {
      "timestamp": { "type": "date" },
      "workflow": { "type": "keyword" },
      "session_id": { "type": "keyword" },
      "user_id": { "type": "keyword" },
      "domain": { "type": "keyword" },
      "decision": { "type": "keyword" },
      "score": { "type": "float" },
      "phase": { "type": "keyword" }
    }
  }
}
```

### Step 3: Import Workflows

1. Go to **Kibana → Management → Workflows**
2. Click **Import**
3. Select the workflow YAML file
4. Review and confirm

Or via API:

```bash
curl -X POST "https://your-kibana/api/workflows" \
  -H "Authorization: ApiKey YOUR_API_KEY" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/x-yaml" \
  --data-binary @full-pipeline-workflow.yml
```

### Step 4: Verify Workflow

```bash
python verify-workflows.py --file full-pipeline-workflow.yml --verbose
```

### Step 5: Test the Workflow

```bash
curl -X POST "https://your-kibana/api/workflows/rogue-full-pipeline/execute" \
  -H "Authorization: ApiKey YOUR_API_KEY" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{
    "inputs": {
      "user_input": "What is Elasticsearch?",
      "agent_id": "your-agent-id",
      "session_id": "test-session-123",
      "domain": "general"
    }
  }'
```

---

## Policy Configuration

### Domain-Specific Policies

| Domain | Confidence | Input Checks | Output Checks | Assertions |
|--------|------------|--------------|---------------|------------|
| Healthcare | 95% | Injection, Content | All + Grounding | No diagnoses, recommend professionals |
| Finance | 90% | Injection, Content | Hallucination, Content, PII | No guarantees, risk disclosures |
| Legal | 90% | Injection, Content | Hallucination, Content | No specific advice, recommend lawyers |
| Customer Service | 85% | Injection, Content | Hallucination, Content, PII | N/A |
| Research | 70% | Injection, Content | Content only | N/A |

### Custom Assertions Example

```yaml
assertions:
  - "The response must not provide specific medical diagnoses"
  - "The response must recommend consulting healthcare professionals"
  - "The response must not prescribe medications or dosages"
```

### Policy Files

- `policies/healthcare-pipeline.yml` - Medical/health use cases
- `policies/finance-pipeline.yml` - Financial services
- `policies/customer-service-pipeline.yml` - Support interactions
- `policies/research-pipeline.yml` - Academic/exploratory

---

## Comparison: Workflows vs API Proxy

| Feature | Mandatory Workflows | API Proxy |
|---------|---------------------|-----------|
| **Integration** | Native to Elastic | External service |
| **Bypass Risk** | Low (within workflow) | None (network level) |
| **Flexibility** | High (configurable) | Medium |
| **Performance** | Optimized | Additional hop |
| **Audit Trail** | Built-in Elasticsearch | Requires setup |
| **Use Case** | Workflow-based agents | Direct API access |

### When to Use Each

**Use Mandatory Workflows when:**
- You're using Elastic Workflows for orchestration
- You need domain-specific policy selection
- You want native Elasticsearch logging
- You need flexible, configurable validation

**Use API Proxy when:**
- You need guaranteed bypass prevention
- Applications call Agent Builder API directly
- You want centralized validation
- You need network-level interception

**Best Practice:** Use both for defense in depth:
1. Mandatory workflows for workflow-based agents
2. API proxy as a fallback for direct API access

---

## Troubleshooting

### Common Issues

#### 1. Workflow Not Triggering

**Symptoms:** No validation happens, responses pass through unvalidated

**Solutions:**
- Verify workflow is `enabled: true`
- Check trigger configuration
- Ensure workflow is properly imported
- Verify secrets are accessible

#### 2. Rogue Security API Errors

**Symptoms:** 401/403 errors, validation always fails

**Solutions:**
```bash
# Test API connectivity
curl -X POST "https://api.rogue.security/api/v1/evaluation/evaluate" \
  -H "X-Rogue-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"messages": [{"role": "user", "content": "test"}], "content_moderation_check": true}'
```

- Verify API key is correct
- Check API key permissions
- Ensure key is properly stored in secrets

#### 3. Template Variable Errors

**Symptoms:** "undefined variable" errors

**Solutions:**
- Use `{{ }}` syntax, not `${}`
- Check variable paths: `steps.step_name.output.data`
- Verify input parameters are defined
- Check for typos in variable names

#### 4. Conditional Logic Not Working

**Symptoms:** Wrong branch executed, unexpected behavior

**Solutions:**
```yaml
# Correct syntax for Elastic Workflows
condition: "steps.validate.output.body.data.status: success"

# Not Jinja-style (deprecated)
condition: "{{ steps.validate.output.data.status == 'success' }}"
```

- Use the colon syntax: `"steps.name.output.body.data.field: value"`
- Check the full output path including `.body.` for HTTP responses
- Verify the data structure being compared

#### 5. Timeout Errors

**Symptoms:** Validation times out, slow responses

**Solutions:**
- Increase timeout values
- Check Rogue Security API latency
- Reduce number of enabled checks
- Consider async validation for non-critical flows

### Debug Mode

Add console logging to debug workflows:

```yaml
- name: debug_output
  type: console
  with:
    message: "Validation result: {{ steps.validate.output | json }}"
```

---

## Best Practices

### 1. Defense in Depth

- Use input validation AND output validation
- Never rely on a single check
- Combine workflows with API proxy for maximum security

### 2. Appropriate Thresholds

- Higher thresholds (90%+) for regulated industries
- Lower thresholds (70-80%) for research/exploratory
- Test thresholds with real data before production

### 3. Comprehensive Logging

- Log ALL validation decisions
- Include session context for debugging
- Store original content hashes (not content) for blocked responses
- Create dashboards for monitoring

### 4. Error Handling

- Always provide safe fallback responses
- Log errors for debugging
- Never expose internal error details to users
- Implement circuit breakers for API failures

### 5. Regular Review

- Audit blocked content patterns
- Review false positive rates
- Update assertions based on new requirements
- Test workflows after updates

---

## File Structure

```
mandatory-workflows/
├── input-gating-workflow.yml      # Input validation only
├── output-validation-workflow.yml  # Output validation only
├── full-pipeline-workflow.yml      # Complete pipeline
├── policies/
│   ├── healthcare-pipeline.yml     # Medical use cases
│   ├── finance-pipeline.yml        # Financial services
│   ├── customer-service-pipeline.yml
│   └── research-pipeline.yml       # Academic use
├── verify-workflows.py             # Validation script
└── MANDATORY_WORKFLOWS_GUIDE.md    # This guide
```

---

## Resources

- [Rogue Security Documentation](https://docs.rogue.security)
- [Rogue Security API Reference](https://docs.rogue.security/api)
- [Elastic Workflows Documentation](https://www.elastic.co/docs/explore-analyze/workflows)
- [Elastic Agent Builder](https://www.elastic.co/docs/explore-analyze/ai-features/agent-builder)

---

## Support

- **Rogue Security**: support@rogue.security
- **GitHub Issues**: [elastic-agent-builder/issues](https://github.com/roguesecurity/elastic-agent-builder-integration/issues)
