# app/analysis/ai_analyst.py

import json

from app.analysis.analyst_model import AnalystModel
from app.analysis.assessment import SecurityAssessment
from app.analysis.model_provider import ModelProvider


class AIAnalyst(AnalystModel):
    """
    AI-backed implementation of VAJRA's Security Analyst.

    Converts structured Evidence into a prompt, sends it to the
    configured ModelProvider, validates/normalizes the model's
    JSON response, and converts it into a SecurityAssessment.
    """

    REQUIRED_FIELDS = [
        "confirmed",
        "confidence",
        "vulnerability_type",
        "severity",
        "root_cause",
        "impact",
        "recommended_action",
        "evidence_summary",
        "limitations",
    ]

    def __init__(self, provider: ModelProvider):
        self.provider = provider

    def analyze(self, evidence):
        """
        Analyze one Evidence object using the configured AI model.
        """

        prompt = self._build_prompt(evidence)

        response = self.provider.generate(prompt)

        return self._parse_response(response)

    def analyze_all(self, evidence_list):
        """
        Analyze multiple Evidence objects.
        """

        return [
            self.analyze(evidence)
            for evidence in evidence_list
        ]

    def _build_prompt(self, evidence):
        """
        Build a strict evidence-grounded security analysis prompt.
        """

        return f"""
You are the Security Analyst component of VAJRA.

Your job is to assess ONE security finding using ONLY the
provided evidence.

Do not invent facts.

Do not assume attacker control unless the evidence supports it.

Distinguish between:
1. What the evidence proves.
2. What is only possible or uncertain.

Return ONLY valid JSON.

The JSON MUST use exactly these fields:

{{
  "confirmed": true,
  "confidence": 0.0,
  "vulnerability_type": "string",
  "severity": "low",
  "root_cause": "string",
  "impact": "string",
  "recommended_action": "string",
  "evidence_summary": ["string"],
  "limitations": ["string"]
}}

STRICT OUTPUT RULES:

- "confirmed" MUST be true or false.
- "confidence" MUST be a NUMBER between 0.0 and 1.0.
- "severity" MUST be one of:
  "low", "medium", "high", "critical".
- "evidence_summary" MUST be a JSON array of strings.
- "limitations" MUST be a JSON array of strings.
- Do NOT return "confidence": "high".
- Do NOT return markdown.
- Do NOT wrap the JSON in ```.

Evidence:

Repository:
{evidence.repository}

File:
{evidence.file}

Function:
{evidence.function}

Line:
{evidence.line}

Vulnerability Type:
{evidence.vulnerability_type}

Severity:
{evidence.severity}

Static Analysis Finding:
{evidence.static_finding}

Dynamic Analysis Evidence:
{evidence.dynamic_analysis}

Fuzzing Evidence:
{evidence.fuzzing}

Historical Evidence:
{evidence.history}
""".strip()

    def _parse_response(self, response):
        """
        Parse and validate the model's JSON response.

        The model is not trusted to perfectly follow the schema.
        Invalid or ambiguous output is rejected rather than silently
        converted into a potentially misleading assessment.
        """

        try:
            data = json.loads(response)
        except json.JSONDecodeError as exc:
            raise ValueError(
                "AI Security Analyst returned invalid JSON."
            ) from exc

        if not isinstance(data, dict):
            raise ValueError(
                "AI Security Analyst response must be a JSON object."
            )

        missing = [
            field
            for field in self.REQUIRED_FIELDS
            if field not in data
        ]

        if missing:
            raise ValueError(
                "AI Security Analyst response is missing fields: "
                + ", ".join(missing)
            )

        # confirmed
        if not isinstance(data["confirmed"], bool):
            raise ValueError(
                "AI Security Analyst 'confirmed' must be a boolean."
            )

        # confidence
        confidence = data["confidence"]

        # bool is technically an int in Python, but it is not a valid
        # confidence value for VAJRA.
        if isinstance(confidence, bool):
            raise ValueError(
                "AI Security Analyst 'confidence' must be a number "
                "between 0.0 and 1.0."
            )

        if not isinstance(confidence, (int, float)):
            raise ValueError(
                "AI Security Analyst 'confidence' must be a number "
                "between 0.0 and 1.0."
            )

        confidence = float(confidence)

        if not 0.0 <= confidence <= 1.0:
            raise ValueError(
                "AI Security Analyst 'confidence' must be between "
                "0.0 and 1.0."
            )

        # vulnerability type
        if not isinstance(data["vulnerability_type"], str):
            raise ValueError(
                "AI Security Analyst 'vulnerability_type' must be a string."
            )

        # severity
        severity = data["severity"]

        if not isinstance(severity, str):
            raise ValueError(
                "AI Security Analyst 'severity' must be a string."
            )

        severity = severity.lower().strip()

        allowed_severities = {
            "low",
            "medium",
            "high",
            "critical",
        }

        if severity not in allowed_severities:
            raise ValueError(
                "AI Security Analyst returned unsupported severity: "
                f"{severity!r}. Expected one of: "
                "low, medium, high, critical."
            )

        # Text fields
        text_fields = [
            "root_cause",
            "impact",
            "recommended_action",
        ]

        for field in text_fields:
            if not isinstance(data[field], str):
                raise ValueError(
                    f"AI Security Analyst '{field}' must be a string."
                )

        # List fields
        list_fields = [
            "evidence_summary",
            "limitations",
        ]

        for field in list_fields:
            if not isinstance(data[field], list):
                raise ValueError(
                    f"AI Security Analyst '{field}' must be a list."
                )

            if not all(
                isinstance(item, str)
                for item in data[field]
            ):
                raise ValueError(
                    f"AI Security Analyst '{field}' must contain "
                    "only strings."
                )

        return SecurityAssessment(
            confirmed=data["confirmed"],
            confidence=confidence,
            vulnerability_type=data["vulnerability_type"],
            severity=severity,
            root_cause=data["root_cause"],
            impact=data["impact"],
            recommended_action=data["recommended_action"],
            evidence_summary=data["evidence_summary"],
            limitations=data["limitations"],
        )