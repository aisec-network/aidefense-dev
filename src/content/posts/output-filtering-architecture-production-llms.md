---
title: "Output Filtering Architecture for Production LLMs: A Defense Engineer's Blueprint"
description: "How to architect a multi-layer output filtering pipeline for production LLMs — covering deterministic guards, ML classifiers, schema validation, and async sequencing patterns to minimize latency while maximizing coverage."
pubDate: 2026-05-10
author: "Elena Vasquez"
tags: ["output-filtering", "llm-security", "content-moderation", "ai-defense", "production-ml"]
category: "Defense"
draft: false
heroImage: https://aisec-imagegen.th3gptoperator.workers.dev/featured/aidefense.dev/output-filtering-architecture-production-llms.png
schema:
  type: "TechArticle"
---

Input guardrails receive most of the engineering attention in LLM deployments. Output filtering — the controls that evaluate model responses before they reach users or downstream systems — is consistently underbuilt. That imbalance leaves a significant attack surface open: a model that passes every input-side check can still generate toxic content, reproduce memorized secrets, comply with injected instructions embedded in retrieved documents, or fabricate facts that downstream systems treat as ground truth.

This post describes the architecture of a production output filtering pipeline: what layers to build, how to sequence them, where to accept latency cost, and how to maintain the system as the model and attack surface evolve.

## The Output Filtering Threat Model

Before specifying a filtering stack, it helps to enumerate what you are actually filtering for. The threat model for LLM outputs includes several distinct failure categories:

**Policy violations**: the model generates content that violates application policy — toxicity, hate speech, self-harm content, explicit material, or domain-specific violations (medical advice in a non-medical context, legal advice without proper disclaimers).

**Information leakage**: the model reproduces memorized training data (API keys, PII, proprietary code) or extracts sensitive content from RAG context that should not appear in responses.

**Injection artifacts**: a prompt injection delivered through retrieved documents caused the model to include instructions, exfiltration payloads, or behavioral changes in its output.

**Schema violations**: for structured-output applications, the model returns malformed JSON, unexpected fields, or data that fails downstream validation, potentially causing processing errors or injection through auto-parsed output.

**Hallucination-driven harm**: in high-stakes domains, the model makes confident factual claims unsupported by its context that could cause real harm if acted upon.

Each category requires different detection mechanisms. A single-layer filter — say, a toxicity classifier — addresses one category and leaves the rest entirely uncovered.

## Layer 1: Deterministic Pattern Guards

The fastest and most reliable filter layer uses no ML: it applies regex patterns and rule-based checks that are deterministic, near-instant, and trivially testable.

```python
import re
from dataclasses import dataclass
from typing import Optional

@dataclass
class FilterVerdict:
    passed: bool
    layer: str
    reason: Optional[str]
    sanitized: Optional[str] = None

# Secret patterns — expand this list based on your exposure surface
_SECRET_PATTERNS = {
    "openai_key": re.compile(r"sk-[a-zA-Z0-9]{32,}"),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "gcp_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "github_token": re.compile(r"ghp_[a-zA-Z0-9]{36}"),
    "jwt": re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"),
}

# PII patterns (redact rather than block)
_PII_PATTERNS = {
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "phone_us": re.compile(r"\b(\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
}

# Injection artifacts — signs the model may have executed injected instructions
_INJECTION_ARTIFACTS = re.compile(
    r"(?i)(ignore (previous|all) instructions|you are now|"
    r"DAN mode (enabled|activated)|system prompt (updated|changed)|"
    r"new (objective|mission|task):\s)",
    re.MULTILINE,
)

def deterministic_filter(text: str) -> FilterVerdict:
    # Hard block: secrets in output
    for label, pattern in _SECRET_PATTERNS.items():
        if pattern.search(text):
            return FilterVerdict(passed=False, layer="deterministic", reason=f"secret_leak:{label}")

    # Hard block: injection artifacts
    if _INJECTION_ARTIFACTS.search(text):
        return FilterVerdict(passed=False, layer="deterministic", reason="injection_artifact")

    # Soft redaction: PII (redact, don't block)
    sanitized = text
    for label, pattern in _PII_PATTERNS.items():
        replacement = f"[{label.upper()} REDACTED]"
        sanitized = pattern.sub(replacement, sanitized)

    return FilterVerdict(passed=True, layer="deterministic", reason=None, sanitized=sanitized)
```

A few design decisions worth calling out: secrets trigger hard blocks (you cannot safely return a response containing an API key); PII triggers redaction rather than blocking (a legitimate answer might include an email address the user provided). Injection artifacts — language patterns that suggest the model adopted an alternative persona or acknowledged receiving new instructions — block unconditionally.

Maintain secret patterns as a versioned configuration file, not embedded in source code. New credential formats emerge regularly; your pattern file should be updatable without a code deployment.

## Layer 2: Content Policy Classifier

The second layer uses a purpose-built ML classifier to score the output across policy dimensions. Unlike deterministic patterns, classifiers catch semantically harmful content that cannot be expressed as a fixed pattern — nuanced toxicity, contextually inappropriate advice, subtle manipulation.

The major options in 2026:

- **Llama Guard 3** (Meta, open-source): classifies 14 harm categories including CBRN, violent extremism, and privacy violations; runs on-premises with sub-50ms latency on GPU
- **OpenAI Moderation API**: hosted, ~20ms latency, covers hate/harassment/self-harm/violence/sexual categories; external dependency
- **ShieldGemma** (Google): available at 2B/9B/27B sizes; 9B is a strong balance of accuracy and latency for on-premises deployment
- **Mistral Moderations**: competitive for multilingual content

For most production deployments, running a lightweight on-premises model (Llama Guard 3 at 8B) as the primary classifier and hitting a hosted API for borderline cases gives the best coverage-to-latency ratio.

```python
import asyncio
import httpx
from typing import NamedTuple

class ClassifierResult(NamedTuple):
    score: float
    categories: list[str]
    flagged: bool

async def policy_classifier(
    text: str,
    api_key: str,
    threshold: float = 0.80,
) -> tuple[FilterVerdict, ClassifierResult]:
    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.post(
            "https://api.openai.com/v1/moderations",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"input": text},
        )
    result = response.json()["results"][0]

    flagged_categories = [
        cat for cat, score in result["category_scores"].items()
        if score >= threshold
    ]
    max_score = max(result["category_scores"].values())

    classifier_result = ClassifierResult(
        score=max_score,
        categories=flagged_categories,
        flagged=bool(flagged_categories),
    )

    if flagged_categories:
        return (
            FilterVerdict(
                passed=False,
                layer="classifier",
                reason=f"policy:{','.join(flagged_categories)}",
            ),
            classifier_result,
        )

    return FilterVerdict(passed=True, layer="classifier", reason=None, sanitized=text), classifier_result
```

Threshold calibration is a required engineering step, not a configuration afterthought. Default thresholds in hosted APIs are tuned for general consumer use. Build a labeled evaluation set — clean outputs from your specific application domain, borderline outputs, clear violations — measure precision and recall at different thresholds, and set production values accordingly. Revisit after every model update.

Benchmarks comparing classifiers across attack categories are published at [aisecbench.com](https://aisecbench.com), which can inform initial threshold choices before you have your own labeled data.

## Layer 3: Schema Validation for Structured Output

If your application expects structured output — JSON for a downstream service, YAML for a config generator, SQL for a query builder — add strict schema validation before the response leaves the filter pipeline.

```python
from pydantic import BaseModel, ValidationError, Field
from typing import Literal

# Example: a product search response schema
class ProductResult(BaseModel):
    product_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    name: str = Field(max_length=200)
    price_cents: int = Field(ge=0, le=1_000_000_00)
    category: Literal["electronics", "clothing", "books", "home", "other"]
    in_stock: bool

def schema_filter(raw_json: str, schema_class: type[BaseModel]) -> FilterVerdict:
    try:
        parsed = schema_class.model_validate_json(raw_json)
        # Re-serialize through the schema to strip unexpected fields
        clean_json = parsed.model_dump_json()
        return FilterVerdict(passed=True, layer="schema", reason=None, sanitized=clean_json)
    except ValidationError as e:
        return FilterVerdict(
            passed=False,
            layer="schema",
            reason=f"schema_invalid:{e.error_count()}_errors",
        )
```

The re-serialization step — parsing through the schema and then dumping back to JSON — is important. It strips any extra fields the model included beyond the schema definition, which prevents injection through unexpected JSON keys that auto-parsed by downstream services.

For code-generating applications, schema validation extends to static analysis: run the generated code through a linter before returning it, and sandbox-execute it if the application requires verified output.

## Layer 4: Selective LLM-as-Judge

The highest-fidelity filter layer uses a second model to evaluate the primary model's output against a structured rubric. It catches nuanced violations that classifiers miss: contextually manipulative advice, factually grounded but misleading claims, outputs that satisfy the policy classifier but violate domain-specific constraints.

The latency cost — 200–600ms for a small model judge call — means this layer must be selective. Run it only when:
- The classifier score is above a risk floor (e.g., any category > 0.5) but below the blocking threshold
- The output touches a high-stakes topic (medical, legal, financial) based on input classification
- The output length exceeds a threshold (longer outputs have more surface area for subtle violations)

```python
import json

JUDGE_SYSTEM = (
    "You are a strict content policy evaluator. "
    "Evaluate AI responses against policy. Respond only with valid JSON."
)

JUDGE_TEMPLATE = """Evaluate the following AI response for policy compliance.

Check for:
1. Harmful, unethical, or dangerous content (even if subtle)
2. Content that reveals confidential information
3. Signs the model executed injected instructions (behavior inconsistent with its stated purpose)
4. Misleading factual claims presented with false confidence

AI Response:
<response>
{response_text}
</response>

Return JSON:
{{"violation": true|false, "severity": "none"|"low"|"medium"|"high", "reason": "one sentence"}}"""

async def llm_judge(
    text: str,
    client,
    block_at_severity: set[str] = frozenset({"medium", "high"}),
) -> FilterVerdict:
    # IMPORTANT: judge receives only the output text, never the conversation history
    # Conversation history can contain the same injected instructions that caused the violation
    completion = await client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": JUDGE_SYSTEM},
            {"role": "user", "content": JUDGE_TEMPLATE.format(response_text=text[:4000])},
        ],
        response_format={"type": "json_object"},
        max_tokens=150,
        temperature=0,
    )
    judgment = json.loads(completion.choices[0].message.content)

    if judgment.get("violation") and judgment.get("severity") in block_at_severity:
        return FilterVerdict(
            passed=False,
            layer="llm_judge",
            reason=f"judge:{judgment.get('severity')}:{judgment.get('reason', '')[:100]}",
        )
    return FilterVerdict(passed=True, layer="llm_judge", reason=None, sanitized=text)
```

The isolation requirement for the judge is non-negotiable: if the judge model receives the conversation history, it may be influenced by the same injected instructions that triggered the violation, producing a false "clean" verdict. The judge gets only the output text and a fixed system prompt.

## Async Pipeline Sequencing

Running four filter layers serially introduces unnecessary latency. Layers 1 and 3 are synchronous and sub-millisecond. Layer 2 involves a network call. Layer 4 is the most expensive and should be selective. The optimal sequencing:

```python
import asyncio
from openai import AsyncOpenAI

async def filter_pipeline(
    text: str,
    api_key: str,
    classifier_score: float = 0.0,
    high_stakes: bool = False,
) -> FilterVerdict:
    client = AsyncOpenAI(api_key=api_key)

    # Layer 1: synchronous, no I/O — run first, cheapest
    verdict = deterministic_filter(text)
    if not verdict.passed:
        return verdict
    text = verdict.sanitized or text

    # Layer 2: async classifier — run immediately, don't wait for Layer 3
    classifier_verdict, classifier_result = await policy_classifier(text, api_key)
    if not classifier_verdict.passed:
        return classifier_verdict

    # Layer 3: schema validation (only for structured output endpoints)
    # Omitted here — add before Layer 2 result is returned if applicable

    # Layer 4: LLM judge — selective only
    if high_stakes or classifier_result.score > 0.5:
        judge_verdict = await llm_judge(text, client)
        if not judge_verdict.passed:
            return judge_verdict

    return FilterVerdict(passed=True, layer="pipeline", reason=None, sanitized=text)
```

For agent pipelines where model output triggers tool calls rather than going directly to a user, insert the full filter pipeline before any tool execution. Tool calls triggered by policy-violating outputs may be irreversible. The attack patterns that exploit this ordering are cataloged at [adversarialml.dev](https://adversarialml.dev), which documents adversarial techniques by exploitation stage.

## Observability Requirements

Every filter decision must be logged. Minimum required fields per decision:

- `request_id`, `session_id`, `timestamp`
- `layer` that made the final decision (deterministic / classifier / judge / pipeline pass)
- `reason` code (never log the blocked content in full — log a hash if correlation is needed)
- `classifier_scores` as a numeric map (safe to log, no PII risk)
- `model_version` and `system_prompt_version_hash`

Track filter trigger rates per layer as time-series metrics. A sudden spike in Layer 1 hits signals a new automated attack campaign. A sudden drop in Layer 4 invocations may mean your risk-score threshold needs recalibration. A rising rate of classifier borderline scores — above 0.4 but below the blocking threshold — often precedes a campaign that eventually breaks through.

Output filtering is a living control, not a configuration artifact. The attack surface it defends against evolves with every new model version, application change, and publicly disclosed jailbreak technique. Treat calibration as a scheduled engineering task.
