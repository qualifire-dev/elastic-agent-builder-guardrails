#!/usr/bin/env python3
"""
Workflow Verification Script
============================

Validates Elastic Workflow YAML files for:
1. YAML syntax correctness
2. Required fields presence
3. Step type validity
4. Template variable references
5. Conditional logic structure
6. Rogue Security API integration

Usage:
    python verify-workflows.py                    # Verify all workflows
    python verify-workflows.py --file input.yml  # Verify specific file
    python verify-workflows.py --strict          # Strict mode (warnings as errors)
"""

import os
import sys
import re
import argparse
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass, field

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML not installed. Run: pip install pyyaml")
    sys.exit(1)


# =============================================================================
# Configuration
# =============================================================================

VALID_STEP_TYPES = {
    # Core step types
    "http",
    "set",
    "return",
    "console",
    "if",
    "foreach",
    "parallel",
    "sleep",
    "fail",

    # Elasticsearch step types
    "elasticsearch.index",
    "elasticsearch.search",
    "elasticsearch.request",
    "elasticsearch.indices.exists",
    "elasticsearch.indices.create",
    "elasticsearch.indices.delete",
    "elasticsearch.bulk",

    # Kibana step types
    "kibana.request",

    # AI/Agent step types
    "ai.agent",
    "ai.chat",
}

REQUIRED_WORKFLOW_FIELDS = {"name"}
RECOMMENDED_WORKFLOW_FIELDS = {"description", "enabled", "triggers", "steps", "inputs"}

REQUIRED_STEP_FIELDS = {"name", "type"}

TEMPLATE_PATTERN = re.compile(r'\{\{\s*([^}]+)\s*\}\}')
VARIABLE_PATTERN = re.compile(r'\$\{([^}]+)\}')


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class ValidationResult:
    """Result of a validation check."""
    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    info: List[str] = field(default_factory=list)


@dataclass
class WorkflowValidation:
    """Complete validation result for a workflow file."""
    file_path: str
    valid: bool
    yaml_valid: bool
    structure_valid: bool
    steps_valid: bool
    templates_valid: bool
    rogue_integration_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    info: List[str] = field(default_factory=list)


# =============================================================================
# Validation Functions
# =============================================================================

def validate_yaml_syntax(content: str) -> Tuple[bool, Optional[Dict], Optional[str]]:
    """Validate YAML syntax and parse content."""
    try:
        data = yaml.safe_load(content)
        return True, data, None
    except yaml.YAMLError as e:
        return False, None, str(e)


def validate_workflow_structure(data: Dict) -> ValidationResult:
    """Validate workflow structure and required fields."""
    result = ValidationResult(valid=True)

    if not isinstance(data, dict):
        result.valid = False
        result.errors.append("Workflow must be a YAML dictionary/object")
        return result

    # Check required fields
    for field in REQUIRED_WORKFLOW_FIELDS:
        if field not in data:
            result.valid = False
            result.errors.append(f"Missing required field: '{field}'")

    # Check recommended fields
    for field in RECOMMENDED_WORKFLOW_FIELDS:
        if field not in data:
            result.warnings.append(f"Missing recommended field: '{field}'")

    # Validate version (optional)
    if "version" in data:
        version = str(data["version"])
        if version not in ["1", "1.0", "\"1\""]:
            result.info.append(f"Version specified: '{version}'")

    # Validate enabled field
    if "enabled" in data and not isinstance(data["enabled"], bool):
        result.warnings.append("'enabled' should be a boolean (true/false)")

    # Validate triggers
    if "triggers" in data:
        if not isinstance(data["triggers"], list):
            result.errors.append("'triggers' must be a list")
            result.valid = False
        else:
            for i, trigger in enumerate(data["triggers"]):
                if not isinstance(trigger, dict):
                    result.errors.append(f"Trigger {i} must be a dictionary")
                elif "type" not in trigger:
                    result.warnings.append(f"Trigger {i} missing 'type' field")

    # Validate inputs
    if "inputs" in data:
        if not isinstance(data["inputs"], list):
            result.errors.append("'inputs' must be a list")
            result.valid = False
        else:
            for i, inp in enumerate(data["inputs"]):
                if not isinstance(inp, dict):
                    result.errors.append(f"Input {i} must be a dictionary")
                elif "name" not in inp:
                    result.errors.append(f"Input {i} missing required 'name' field")
                elif "type" not in inp:
                    result.warnings.append(f"Input '{inp.get('name', i)}' missing 'type' field")

    return result


def validate_step(step: Dict, step_path: str, defined_steps: set) -> ValidationResult:
    """Validate a single step."""
    result = ValidationResult(valid=True)

    if not isinstance(step, dict):
        result.valid = False
        result.errors.append(f"{step_path}: Step must be a dictionary")
        return result

    # Check required fields
    for field in REQUIRED_STEP_FIELDS:
        if field not in step:
            result.valid = False
            result.errors.append(f"{step_path}: Missing required field '{field}'")

    step_name = step.get("name", "unnamed")
    step_type = step.get("type", "unknown")

    # Track step name for reference validation
    if "name" in step:
        defined_steps.add(step_name)

    # Validate step type
    if step_type not in VALID_STEP_TYPES:
        result.warnings.append(
            f"{step_path}: Unknown step type '{step_type}'. "
            f"Valid types: {', '.join(sorted(VALID_STEP_TYPES)[:10])}..."
        )

    # Validate HTTP steps
    if step_type == "http":
        validate_http_step(step, step_path, result)

    # Validate conditional steps
    if step_type == "if":
        validate_if_step(step, step_path, result, defined_steps)

    # Validate foreach steps
    if step_type == "foreach":
        validate_foreach_step(step, step_path, result, defined_steps)

    # Validate nested steps
    if "steps" in step and step_type != "if":
        for i, nested_step in enumerate(step.get("steps", [])):
            nested_result = validate_step(
                nested_step,
                f"{step_path}.steps[{i}]",
                defined_steps
            )
            result.errors.extend(nested_result.errors)
            result.warnings.extend(nested_result.warnings)
            if not nested_result.valid:
                result.valid = False

    return result


def validate_http_step(step: Dict, step_path: str, result: ValidationResult):
    """Validate HTTP step configuration."""
    with_config = step.get("with", {})

    if not with_config:
        result.errors.append(f"{step_path}: HTTP step missing 'with' configuration")
        result.valid = False
        return

    # Check required HTTP fields
    if "url" not in with_config:
        result.errors.append(f"{step_path}: HTTP step missing 'url'")
        result.valid = False

    if "method" not in with_config:
        result.warnings.append(f"{step_path}: HTTP step missing 'method' (defaults to GET)")
    else:
        valid_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
        method = with_config["method"].upper() if isinstance(with_config["method"], str) else ""
        if method not in valid_methods:
            result.warnings.append(f"{step_path}: Unusual HTTP method '{method}'")

    # Check for timeout
    if "timeout" not in with_config:
        result.info.append(f"{step_path}: Consider adding 'timeout' for HTTP step")


def validate_if_step(step: Dict, step_path: str, result: ValidationResult, defined_steps: set):
    """Validate conditional (if) step."""
    if "condition" not in step:
        result.errors.append(f"{step_path}: 'if' step missing 'condition'")
        result.valid = False

    if "steps" not in step:
        result.warnings.append(f"{step_path}: 'if' step has no 'steps' for true case")
    else:
        for i, nested_step in enumerate(step.get("steps", [])):
            nested_result = validate_step(
                nested_step,
                f"{step_path}.steps[{i}]",
                defined_steps
            )
            result.errors.extend(nested_result.errors)
            result.warnings.extend(nested_result.warnings)
            if not nested_result.valid:
                result.valid = False

    if "else" in step:
        for i, nested_step in enumerate(step.get("else", [])):
            nested_result = validate_step(
                nested_step,
                f"{step_path}.else[{i}]",
                defined_steps
            )
            result.errors.extend(nested_result.errors)
            result.warnings.extend(nested_result.warnings)
            if not nested_result.valid:
                result.valid = False


def validate_foreach_step(step: Dict, step_path: str, result: ValidationResult, defined_steps: set):
    """Validate foreach step."""
    if "foreach" not in step and "items" not in step:
        result.errors.append(f"{step_path}: 'foreach' step missing iteration source")
        result.valid = False

    if "steps" not in step:
        result.errors.append(f"{step_path}: 'foreach' step has no 'steps'")
        result.valid = False


def validate_steps(data: Dict) -> ValidationResult:
    """Validate all steps in the workflow."""
    result = ValidationResult(valid=True)
    defined_steps = set()

    steps = data.get("steps", [])
    if not isinstance(steps, list):
        result.valid = False
        result.errors.append("'steps' must be a list")
        return result

    if len(steps) == 0:
        result.warnings.append("Workflow has no steps defined")

    for i, step in enumerate(steps):
        step_result = validate_step(step, f"steps[{i}]", defined_steps)
        result.errors.extend(step_result.errors)
        result.warnings.extend(step_result.warnings)
        result.info.extend(step_result.info)
        if not step_result.valid:
            result.valid = False

    return result


def validate_templates(content: str, data: Dict) -> ValidationResult:
    """Validate template variable references."""
    result = ValidationResult(valid=True)

    # Find all template references
    jinja_templates = TEMPLATE_PATTERN.findall(content)
    dollar_templates = VARIABLE_PATTERN.findall(content)

    # Collect defined variables
    defined_vars = set()

    # Add inputs
    for inp in data.get("inputs", []):
        if "name" in inp:
            defined_vars.add(f"inputs.{inp['name']}")

    # Add consts
    for const_name in data.get("consts", {}).keys():
        defined_vars.add(f"consts.{const_name}")

    # Add secrets (common ones)
    common_secrets = {"rogue_api_key", "elastic_api_key", "kibana_url"}
    for secret in common_secrets:
        defined_vars.add(f"secrets.{secret}")

    # Check for undefined references (basic check)
    for template in jinja_templates:
        template = template.strip()
        # Skip complex expressions
        if '|' in template or '==' in template or 'for' in template:
            continue

        base_ref = template.split('.')[0].split('[')[0].strip()
        valid_prefixes = {"inputs", "steps", "consts", "secrets", "foreach", "now", "error"}

        if base_ref not in valid_prefixes:
            result.warnings.append(f"Unusual template reference: '{{{{ {template} }}}}'")

    # Info about template usage
    result.info.append(f"Found {len(jinja_templates)} Jinja-style templates ({{{{ }}}})")
    result.info.append(f"Found {len(dollar_templates)} dollar-style templates (${{}})")

    if dollar_templates:
        result.warnings.append(
            "Dollar-style templates (${}) detected. "
            "Elastic Workflows prefer Jinja-style ({{ }})"
        )

    return result


def validate_rogue_integration(data: Dict) -> ValidationResult:
    """Validate Rogue Security API integration."""
    result = ValidationResult(valid=True)

    rogue_api_calls = 0
    has_input_validation = False
    has_output_validation = False

    def check_step_for_rogue(step: Dict, path: str):
        nonlocal rogue_api_calls, has_input_validation, has_output_validation

        step_type = step.get("type", "")
        with_config = step.get("with", {})

        # Check HTTP steps for Rogue API calls
        if step_type == "http":
            url = str(with_config.get("url", ""))
            if "rogue.security" in url or "rogue_api" in url:
                rogue_api_calls += 1

                body = with_config.get("body", "")
                body_str = str(body).lower()

                if "policy_target" in body_str and "input" in body_str:
                    has_input_validation = True
                if "hallucinations_check" in body_str or "content_moderation" in body_str:
                    has_output_validation = True

        # Check nested steps
        for nested in step.get("steps", []):
            check_step_for_rogue(nested, f"{path}.steps")
        for nested in step.get("else", []):
            check_step_for_rogue(nested, f"{path}.else")

    # Check all steps
    for i, step in enumerate(data.get("steps", [])):
        check_step_for_rogue(step, f"steps[{i}]")

    # Report findings
    result.info.append(f"Found {rogue_api_calls} Rogue Security API call(s)")

    if rogue_api_calls == 0:
        result.warnings.append("No Rogue Security API integration detected")

    if has_input_validation:
        result.info.append("Input validation (gating) detected")
    else:
        result.warnings.append("No input validation/gating detected")

    if has_output_validation:
        result.info.append("Output validation detected")
    else:
        result.warnings.append("No output validation detected")

    # Check for API key handling
    content_str = str(data)
    if "rogue_api_key" in content_str.lower() or "X-Rogue-API-Key" in content_str:
        result.info.append("Rogue API key reference found")
    else:
        result.warnings.append("No Rogue API key reference found")

    return result


def validate_workflow_file(file_path: str) -> WorkflowValidation:
    """Validate a single workflow file."""
    result = WorkflowValidation(
        file_path=file_path,
        valid=True,
        yaml_valid=True,
        structure_valid=True,
        steps_valid=True,
        templates_valid=True,
        rogue_integration_valid=True
    )

    # Read file
    try:
        with open(file_path, 'r') as f:
            content = f.read()
    except Exception as e:
        result.valid = False
        result.yaml_valid = False
        result.errors.append(f"Cannot read file: {e}")
        return result

    # Validate YAML syntax
    yaml_valid, data, yaml_error = validate_yaml_syntax(content)
    if not yaml_valid:
        result.valid = False
        result.yaml_valid = False
        result.errors.append(f"YAML syntax error: {yaml_error}")
        return result

    result.info.append("YAML syntax is valid")

    # Validate structure
    structure_result = validate_workflow_structure(data)
    result.errors.extend(structure_result.errors)
    result.warnings.extend(structure_result.warnings)
    if not structure_result.valid:
        result.valid = False
        result.structure_valid = False

    # Validate steps
    steps_result = validate_steps(data)
    result.errors.extend(steps_result.errors)
    result.warnings.extend(steps_result.warnings)
    result.info.extend(steps_result.info)
    if not steps_result.valid:
        result.valid = False
        result.steps_valid = False

    # Validate templates
    templates_result = validate_templates(content, data)
    result.errors.extend(templates_result.errors)
    result.warnings.extend(templates_result.warnings)
    result.info.extend(templates_result.info)
    if not templates_result.valid:
        result.valid = False
        result.templates_valid = False

    # Validate Rogue integration
    rogue_result = validate_rogue_integration(data)
    result.errors.extend(rogue_result.errors)
    result.warnings.extend(rogue_result.warnings)
    result.info.extend(rogue_result.info)
    if not rogue_result.valid:
        result.valid = False
        result.rogue_integration_valid = False

    return result


# =============================================================================
# Main
# =============================================================================

def print_result(result: WorkflowValidation, verbose: bool = False):
    """Print validation result."""
    status = "PASS" if result.valid else "FAIL"
    status_color = "\033[92m" if result.valid else "\033[91m"
    reset_color = "\033[0m"

    print(f"\n{status_color}[{status}]{reset_color} {result.file_path}")

    if result.errors:
        print(f"  \033[91mErrors ({len(result.errors)}):\033[0m")
        for error in result.errors:
            print(f"    - {error}")

    if result.warnings:
        print(f"  \033[93mWarnings ({len(result.warnings)}):\033[0m")
        for warning in result.warnings:
            print(f"    - {warning}")

    if verbose and result.info:
        print(f"  \033[94mInfo ({len(result.info)}):\033[0m")
        for info in result.info:
            print(f"    - {info}")


def main():
    parser = argparse.ArgumentParser(
        description="Validate Elastic Workflow YAML files"
    )
    parser.add_argument(
        "--file", "-f",
        help="Specific file to validate"
    )
    parser.add_argument(
        "--strict", "-s",
        action="store_true",
        help="Treat warnings as errors"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show info messages"
    )
    parser.add_argument(
        "--dir", "-d",
        default=".",
        help="Directory to scan for workflow files"
    )

    args = parser.parse_args()

    print("=" * 60)
    print("Elastic Workflow Validator")
    print("=" * 60)

    # Find files to validate
    if args.file:
        files = [args.file]
    else:
        workflow_dir = Path(args.dir)
        files = list(workflow_dir.glob("**/*.yml")) + list(workflow_dir.glob("**/*.yaml"))
        # Exclude common non-workflow files
        files = [f for f in files if not any(
            x in str(f) for x in [".venv", "node_modules", "__pycache__"]
        )]

    if not files:
        print("\nNo workflow files found.")
        return 0

    print(f"\nValidating {len(files)} file(s)...")

    results = []
    for file_path in files:
        result = validate_workflow_file(str(file_path))
        results.append(result)
        print_result(result, args.verbose)

    # Summary
    print("\n" + "=" * 60)
    passed = sum(1 for r in results if r.valid)
    failed = len(results) - passed
    total_errors = sum(len(r.errors) for r in results)
    total_warnings = sum(len(r.warnings) for r in results)

    print(f"Summary: {passed} passed, {failed} failed")
    print(f"Total: {total_errors} errors, {total_warnings} warnings")

    if args.strict and total_warnings > 0:
        print("\n\033[91mStrict mode: Treating warnings as errors\033[0m")
        return 1

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
