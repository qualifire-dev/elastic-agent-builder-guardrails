#!/usr/bin/env python3
"""
Rogue Security + Elastic Agent Builder Proxy
=============================================

API proxy that intercepts all Elastic Agent Builder responses
and validates them through Rogue Security guardrails using direct API calls.

This ensures NO response can bypass validation.
"""

import json
import logging
import time
import traceback
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
import os
from datetime import datetime
from dotenv import load_dotenv

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Rogue Security API configuration
ROGUE_API_URL = os.getenv("ROGUE_API_URL", "https://api.rogue.security")


@dataclass
class ValidationPolicy:
    """Validation policy configuration"""
    name: str
    confidence_threshold: float = 0.8
    block_unsafe: bool = True
    hallucinations_check: bool = True
    grounding_check: bool = False
    content_moderation_check: bool = True
    pii_check: bool = False
    prompt_injections: bool = False
    tool_use_quality_check: bool = False
    grounding_multi_turn_mode: bool = False
    assertions: List[str] = field(default_factory=list)
    policy_target: str = None


class RogueAPIClient:
    """Direct HTTP client for Rogue Security API"""

    def __init__(self, api_key: str, base_url: str = None):
        self.api_key = api_key
        self.base_url = (base_url or ROGUE_API_URL).rstrip("/")
        self.client = httpx.AsyncClient(
            timeout=30.0,
            headers={
                "X-Rogue-API-Key": api_key,
                "Content-Type": "application/json"
            }
        )

    async def evaluate(
        self,
        messages: List[Dict[str, str]],
        hallucinations_check: bool = False,
        grounding_check: bool = False,
        content_moderation_check: bool = False,
        pii_check: bool = False,
        prompt_injections: bool = False,
        tool_use_quality_check: bool = False,
        grounding_multi_turn_mode: bool = None,
        assertions: List[str] = None,
        policy_target: str = None
    ) -> Dict[str, Any]:
        """Call Rogue Security evaluation API"""

        payload = {
            "messages": messages,
            "hallucinations_check": hallucinations_check,
            "grounding_check": grounding_check,
            "content_moderation_check": content_moderation_check,
            "pii_check": pii_check,
            "prompt_injections": prompt_injections,
            "tool_use_quality_check": tool_use_quality_check,
        }

        if grounding_multi_turn_mode is not None:
            payload["grounding_multi_turn_mode"] = grounding_multi_turn_mode

        if assertions:
            payload["assertions"] = assertions

        if policy_target:
            payload["policy_target"] = policy_target

        response = await self.client.post(
            f"{self.base_url}/api/v1/evaluation/evaluate",
            json=payload
        )

        if response.status_code != 200:
            error_text = response.text
            raise Exception(f"Rogue Security API error {response.status_code}: {error_text}")

        return response.json()

    async def close(self):
        await self.client.aclose()


class ElasticProxy:
    """Main proxy that intercepts and validates all Agent Builder responses"""

    def __init__(self, kibana_url: str, elastic_api_key: str, rogue_api_key: str):
        self.kibana_url = kibana_url.rstrip("/")
        self.elastic_api_key = elastic_api_key

        # Initialize Rogue Security API client
        self.rogue_client = RogueAPIClient(api_key=rogue_api_key)

        # HTTP client for Elastic API
        self.elastic_client = httpx.AsyncClient(
            timeout=60.0,
            headers={
                "Authorization": f"ApiKey {elastic_api_key}",
                "Content-Type": "application/json",
                "kbn-xsrf": "true"
            }
        )

        # Validation policies
        self.policies = {
            "default": ValidationPolicy(
                name="default",
                confidence_threshold=0.8,
                hallucinations_check=True,
                content_moderation_check=True,
                pii_check=False,
                prompt_injections=False
            ),
            "high_stakes": ValidationPolicy(
                name="high_stakes",
                confidence_threshold=0.9,
                hallucinations_check=True,
                grounding_check=True,
                content_moderation_check=True,
                pii_check=True,
                prompt_injections=True,
                tool_use_quality_check=False,
                grounding_multi_turn_mode=True
            ),
            "public_facing": ValidationPolicy(
                name="public_facing",
                confidence_threshold=0.9,
                hallucinations_check=True,
                content_moderation_check=True,
                pii_check=True,
                prompt_injections=True,
                tool_use_quality_check=False,
                grounding_multi_turn_mode=True
            ),
            "research_mode": ValidationPolicy(
                name="research_mode",
                confidence_threshold=0.7,
                block_unsafe=False,
                hallucinations_check=True,
                grounding_check=True,
                content_moderation_check=False,
                pii_check=False,
                grounding_multi_turn_mode=True
            ),
            "legal_financial": ValidationPolicy(
                name="legal_financial",
                confidence_threshold=0.9,
                block_unsafe=True,
                hallucinations_check=True,
                content_moderation_check=True,
                pii_check=True,
                prompt_injections=False,
                assertions=[
                    "The response must not provide specific legal advice",
                    "The response must not provide specific financial or investment advice",
                    "The response must recommend consulting a professional for legal or financial matters"
                ]
            ),
            "input_gating": ValidationPolicy(
                name="input_gating",
                confidence_threshold=0.9,
                block_unsafe=True,
                hallucinations_check=False,
                content_moderation_check=True,
                pii_check=False,
                prompt_injections=True,
                policy_target="input"
            ),
            "strict_content": ValidationPolicy(
                name="strict_content",
                confidence_threshold=0.95,
                block_unsafe=True,
                hallucinations_check=True,
                content_moderation_check=True,
                pii_check=True,
                prompt_injections=True
            )
        }

    async def close(self):
        await self.elastic_client.aclose()
        await self.rogue_client.close()

    def build_conversation_messages(
        self,
        user_input: str,
        agent_response: str,
        request_data: Dict[str, Any]
    ) -> List[Dict[str, str]]:
        """Build conversation messages from Agent Builder request"""

        messages = []

        # Add system message if present
        system_prompt = request_data.get("system_prompt")
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        # Add conversation history if available
        conversation_history = request_data.get("conversation_history", [])
        for msg in conversation_history:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role and content:
                messages.append({"role": role, "content": content})

        # Add current user input
        messages.append({"role": "user", "content": user_input})

        # Add agent response
        messages.append({"role": "assistant", "content": agent_response})

        return messages

    def get_policy(self, context: Dict[str, Any]) -> ValidationPolicy:
        """Select validation policy based on context"""

        # Check for explicit policy override first
        if context.get("policy_override"):
            policy_name = context.get("policy_override")
            if policy_name in self.policies:
                return self.policies[policy_name]

        if context.get("high_risk"):
            return self.policies["high_stakes"]

        if context.get("public_facing"):
            return self.policies["public_facing"]

        if context.get("research_mode"):
            return self.policies["research_mode"]

        domain = context.get("domain", "").lower()
        if domain in ["healthcare", "finance", "legal"]:
            return self.policies["high_stakes"]

        return self.policies["default"]

    async def validate_response(
        self,
        response_text: str,
        user_input: str,
        agent_id: str,
        context: Dict[str, Any],
        request_data: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Validate agent response through Rogue Security API using messages format"""

        if not response_text.strip():
            return {"response": response_text, "validation_applied": False}

        policy = self.get_policy(context)
        start_time = time.time()

        try:
            # Build conversation messages for better context understanding
            messages = self.build_conversation_messages(
                user_input=user_input,
                agent_response=response_text,
                request_data=request_data or {}
            )

            logger.info(f"Using messages format with {len(messages)} messages")

            # Build evaluation kwargs
            eval_kwargs = {
                "messages": messages,
                "hallucinations_check": policy.hallucinations_check,
                "grounding_check": policy.grounding_check,
                "content_moderation_check": policy.content_moderation_check,
                "pii_check": policy.pii_check,
                "prompt_injections": policy.prompt_injections,
                "tool_use_quality_check": policy.tool_use_quality_check,
            }

            # Only include grounding_multi_turn_mode when grounding_check is enabled
            if policy.grounding_check and policy.grounding_multi_turn_mode:
                eval_kwargs["grounding_multi_turn_mode"] = policy.grounding_multi_turn_mode

            # Include assertions if configured
            if policy.assertions:
                eval_kwargs["assertions"] = policy.assertions

            # Include policy_target if configured (for input gating)
            if policy.policy_target:
                eval_kwargs["policy_target"] = policy.policy_target

            # Log Rogue Security request for debugging
            logger.info(f"Rogue Security API request: {json.dumps(eval_kwargs, indent=2)}")

            result = await self.rogue_client.evaluate(**eval_kwargs)

            validation_time = (time.time() - start_time) * 1000

            # Log Rogue Security response for debugging
            logger.info(f"Rogue Security API response: {json.dumps(result, indent=2)}")

            # Parse results from Qualifire API
            # Overall score from API is in 0-100 range, normalize to 0-1 for consistent comparison
            raw_overall_score = result.get("score") or 0
            overall_score = raw_overall_score / 100 if raw_overall_score > 1 else raw_overall_score
            failed_checks = []
            check_details = {}

            # Process evaluation results
            for eval_result in result.get("evaluationResults", []):
                check_type = eval_result.get("type", "unknown")
                check_details[check_type] = []

                for check in eval_result.get("results", []):
                    check_details[check_type].append({
                        "name": check.get("name", ""),
                        "score": check.get("score", 0),
                        "flagged": check.get("flagged", False),
                        "label": check.get("label", ""),
                        "reason": check.get("reason", ""),
                        "confidence_score": check.get("confidence_score")
                    })

                    # Only fail if Rogue Security explicitly flags the check
                    is_flagged = check.get("flagged", False)

                    if is_flagged:
                        failed_checks.append({
                            "check_type": check_type,
                            "name": check.get("name", ""),
                            "score": check.get("score", 0),
                            "flagged": True,
                            "reason": check.get("reason", "Check failed"),
                            "label": check.get("label", "")
                        })

            # Determine if response should be blocked
            # Only block if any check was explicitly flagged by Rogue Security
            overall_passed = len(failed_checks) == 0

            logger.info(f"Validation decision: overall_score={overall_score}, flagged_checks={len(failed_checks)}, passed={overall_passed}")

            validation_metadata = {
                "validation_applied": True,
                "policy_applied": policy.name,
                "overall_score": overall_score,
                "check_details": check_details,
                "validation_time_ms": round(validation_time, 2),
                "format_used": "messages",
                "message_count": len(messages)
            }

            if overall_passed:
                return {
                    "response": response_text,
                    "validation_status": "passed",
                    **validation_metadata
                }

            elif policy.block_unsafe:
                safe_response = self.generate_safe_response(failed_checks, policy)
                return {
                    "response": safe_response,
                    "validation_status": "blocked_and_replaced",
                    "original_blocked": True,
                    "failed_checks": failed_checks,
                    "block_reason": "Response failed Rogue Security safety validation",
                    **validation_metadata
                }

            else:
                return {
                    "response": response_text,
                    "validation_status": "flagged_but_allowed",
                    "failed_checks": failed_checks,
                    "note": "Response flagged but allowed per policy",
                    **validation_metadata
                }

        except Exception as e:
            logger.error(f"Rogue Security validation failed: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            validation_time = (time.time() - start_time) * 1000

            # On validation error, apply safe default behavior
            error_metadata = {
                "validation_applied": True,
                "policy_applied": policy.name,
                "error": str(e),
                "validation_time_ms": round(validation_time, 2)
            }

            if policy.block_unsafe:
                return {
                    "response": "I apologize, but I cannot provide a response at this time due to a safety system issue. Please try again later.",
                    "validation_status": "error_blocked",
                    **error_metadata
                }
            else:
                return {
                    "response": response_text,
                    "validation_status": "error_allowed",
                    "validation_error": str(e),
                    **error_metadata
                }

    def generate_safe_response(self, failed_checks: List[Dict], policy: ValidationPolicy) -> str:
        """Generate safe alternative response based on failed checks"""

        if not failed_checks:
            return "I need to be more careful with my response to ensure safety and accuracy."

        check_types = [check.get("check_type", "") for check in failed_checks]

        if "hallucinations" in check_types:
            return (
                "I don't have sufficient reliable information to answer that accurately. "
                "Let me search for verified sources to provide you with factual information."
            )

        if "content_moderation" in check_types:
            return (
                "I can't provide that type of content. "
                "How can I help you with something else instead?"
            )

        if "pii" in check_types:
            return (
                "I've detected that my response might contain sensitive personal information. "
                "Let me provide a more appropriate answer without including personal details."
            )

        if "prompt_injections" in check_types:
            return (
                "I noticed something unusual in the request. "
                "Let me provide a helpful response while ensuring security."
            )

        if "tool_use_quality" in check_types:
            return (
                "Let me reconsider the best approach for your request and provide a more appropriate response."
            )

        if "grounding" in check_types:
            return (
                "I want to make sure my response is well-grounded in reliable information. "
                "Let me provide a more careful answer based on verified facts."
            )

        if "assertions" in check_types:
            return (
                "I'm not able to provide specific advice on this topic. "
                "Please consult with a qualified professional for personalized guidance."
            )

        return (
            "I need to be more careful with my response to ensure accuracy and safety. "
            "How can I better help you with your request?"
        )

    async def proxy_request(self, method: str, path: str, headers: Dict, body: bytes = None):
        """Proxy request to Elastic Agent Builder"""

        url = f"{self.kibana_url}{path}"

        try:
            response = await self.elastic_client.request(
                method=method,
                url=url,
                content=body
            )

            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "content": response.content,
                "json": response.json() if response.headers.get("content-type", "").startswith("application/json") else None
            }

        except Exception as e:
            logger.error(f"Proxy request failed: {e}")
            raise HTTPException(status_code=503, detail="Elastic API unavailable")

    def extract_response_text(self, response: Any) -> str:
        """Extract text content from agent response (handles string or dict)"""
        if isinstance(response, str):
            return response
        if isinstance(response, dict):
            for key in ["content", "text", "message", "output"]:
                if key in response and isinstance(response[key], str):
                    return response[key]
            logger.warning(f"Could not extract text from response dict: {list(response.keys())}")
            return json.dumps(response)
        return str(response) if response else ""

    async def handle_converse(self, request_data: Dict[str, Any], context: Dict[str, Any]):
        """Handle converse request with validation"""

        # Strip fields that Elastic doesn't accept, but keep them for validation
        elastic_request_data = {k: v for k, v in request_data.items()
                                 if k not in ["conversation_history", "system_prompt"]}

        # Forward to Elastic (without conversation_history)
        elastic_response = await self.proxy_request(
            method="POST",
            path="/api/agent_builder/converse",
            headers={"Content-Type": "application/json"},
            body=json.dumps(elastic_request_data).encode()
        )

        if elastic_response["json"]:
            response_data = elastic_response["json"]

            try:
                logger.info(f"Elastic response keys: {list(response_data.keys()) if isinstance(response_data, dict) else type(response_data)}")
                raw_response = response_data.get("response", "") if isinstance(response_data, dict) else ""
                logger.info(f"Raw response type: {type(raw_response)}, preview: {str(raw_response)[:100]}")
                agent_response = self.extract_response_text(raw_response)
            except Exception as e:
                logger.error(f"Error extracting response: {e}")
                logger.error(f"Response data: {response_data}")
                logger.error(f"Traceback: {traceback.format_exc()}")
                return JSONResponse(content=response_data, status_code=elastic_response["status_code"])

            if agent_response:
                # Validate response using Rogue Security API
                validation_result = await self.validate_response(
                    response_text=agent_response,
                    user_input=request_data.get("input", ""),
                    agent_id=request_data.get("agent_id", "unknown"),
                    context=context,
                    request_data=request_data
                )

                # Update response with validated content, preserving original structure
                validated_text = validation_result["response"]
                if isinstance(raw_response, dict):
                    for key in ["content", "text", "message", "output"]:
                        if key in raw_response:
                            raw_response[key] = validated_text
                            break
                    response_data["response"] = raw_response
                else:
                    response_data["response"] = validated_text

                response_data["rogue_validation"] = {
                    k: v for k, v in validation_result.items() if k != "response"
                }

            return JSONResponse(content=response_data, status_code=elastic_response["status_code"])

        return Response(
            content=elastic_response["content"],
            status_code=elastic_response["status_code"],
            headers=elastic_response["headers"]
        )


# FastAPI app
app = FastAPI(
    title="Rogue Security + Elastic Agent Builder Proxy",
    description="Guaranteed guardrail validation for all Agent Builder responses using Rogue Security API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global proxy instance
proxy: Optional[ElasticProxy] = None


@app.on_event("startup")
async def startup():
    global proxy

    load_dotenv()

    rogue_api_key = os.getenv("ROGUE_API_KEY")
    kibana_url = os.getenv("KIBANA_URL")
    elastic_api_key = os.getenv("ELASTIC_API_KEY")

    if not all([rogue_api_key, kibana_url, elastic_api_key]):
        raise RuntimeError(
            "Missing required environment variables: ROGUE_API_KEY, KIBANA_URL, ELASTIC_API_KEY"
        )

    proxy = ElasticProxy(kibana_url, elastic_api_key, rogue_api_key)

    logger.info("Rogue Security proxy started with direct API calls - all responses will be validated")


@app.on_event("shutdown")
async def shutdown():
    global proxy
    if proxy:
        await proxy.close()


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "rogue-elastic-proxy",
        "api_version": "v1",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/api/agent_builder/converse")
async def converse_with_validation(request: Request):
    """Converse endpoint with guaranteed Rogue Security validation"""

    if not proxy:
        raise HTTPException(status_code=503, detail="Proxy not ready")

    request_data = await request.json()

    context = {}

    if request.headers.get("x-high-risk") == "true":
        context["high_risk"] = True
    if request.headers.get("x-public-facing") == "true":
        context["public_facing"] = True
    if request.headers.get("x-research-mode") == "true":
        context["research_mode"] = True

    if request.headers.get("x-domain"):
        context["domain"] = request.headers.get("x-domain")

    if request.headers.get("x-rogue-policy"):
        policy_name = request.headers.get("x-rogue-policy")
        if policy_name in proxy.policies:
            context["policy_override"] = policy_name

    return await proxy.handle_converse(request_data, context)


@app.api_route("/api/agent_builder/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy_other_endpoints(path: str, request: Request):
    """Proxy all other Agent Builder endpoints without validation"""

    if not proxy:
        raise HTTPException(status_code=503, detail="Proxy not ready")

    body = await request.body() if request.method in ["POST", "PUT", "PATCH"] else None

    response = await proxy.proxy_request(
        method=request.method,
        path=f"/api/agent_builder/{path}",
        headers=dict(request.headers),
        body=body
    )

    if response["json"]:
        return JSONResponse(content=response["json"], status_code=response["status_code"])

    return Response(
        content=response["content"],
        status_code=response["status_code"]
    )


@app.get("/policies")
async def list_policies():
    """List available validation policies"""

    if not proxy:
        raise HTTPException(status_code=503, detail="Proxy not ready")

    policies = {}
    for name, policy in proxy.policies.items():
        policy_dict = {
            "name": policy.name,
            "confidence_threshold": policy.confidence_threshold,
            "blocks_unsafe": policy.block_unsafe,
            "enabled_checks": {}
        }

        checks = [
            "hallucinations_check", "grounding_check", "content_moderation_check",
            "pii_check", "prompt_injections", "tool_use_quality_check"
        ]
        for check in checks:
            if hasattr(policy, check):
                policy_dict["enabled_checks"][check] = getattr(policy, check)

        if hasattr(policy, "grounding_multi_turn_mode"):
            policy_dict["grounding_multi_turn_mode"] = policy.grounding_multi_turn_mode

        if hasattr(policy, "assertions") and policy.assertions:
            policy_dict["assertions"] = policy.assertions

        if hasattr(policy, "policy_target") and policy.policy_target:
            policy_dict["policy_target"] = policy.policy_target

        policies[name] = policy_dict

    return {"policies": policies}


@app.get("/validate/test")
async def test_validation():
    """Test endpoint to verify Rogue Security API integration"""

    if not proxy:
        raise HTTPException(status_code=503, detail="Proxy not ready")

    try:
        result = await proxy.rogue_client.evaluate(
            messages=[
                {"role": "user", "content": "What is 2+2?"},
                {"role": "assistant", "content": "2+2 equals 4."}
            ],
            hallucinations_check=True
        )

        return {
            "status": "success",
            "api_working": True,
            "sdk_working": True,  # Keep for backwards compatibility
            "test_score": result.get("score"),
            "test_status": result.get("status")
        }

    except Exception as e:
        return {
            "status": "error",
            "api_working": False,
            "sdk_working": False,  # Keep for backwards compatibility
            "error": str(e)
        }


if __name__ == "__main__":
    uvicorn.run(
        "proxy:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info"
    )
