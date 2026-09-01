# app/analysis/deterministic_analyst.py

from app.analysis.assessment import SecurityAssessment
from app.analysis.analyst_model import AnalystModel


class DeterministicAnalyst(AnalystModel):
    """
    Deterministic implementation of VAJRA's Security Analyst.

    This implementation does not use an LLM.

    It converts normalized Evidence objects into structured
    SecurityAssessment objects using predefined vulnerability
    assessment rules.

    This implementation provides a reliable baseline that can
    later be compared against an AI-based Security Analyst.
    """

    def analyze(self, evidence):
        """
        Analyze one normalized Evidence object.
        """

        vulnerability_type = evidence.vulnerability_type

        handler = self._handlers().get(vulnerability_type)

        if handler:
            return handler(evidence)

        return self._generic_assessment(evidence)

    def analyze_all(self, evidence_list):
        """
        Analyze multiple Evidence objects.
        """

        return [
            self.analyze(evidence)
            for evidence in evidence_list
        ]

    def _handlers(self):
        """
        Map vulnerability types to their specialized
        assessment handlers.
        """

        return {
            "unsafe-eval": self._analyze_unsafe_eval,
            "unsafe-exec": self._analyze_unsafe_exec,
            "command-injection-risk": self._analyze_command_injection,
            "unsafe-deserialization": self._analyze_unsafe_deserialization,
            "hardcoded-credential": self._analyze_hardcoded_credential,
            "parse-error": self._analyze_parse_error,
        }

    def _base_evidence(self, evidence):
        """
        Build the common evidence summary shared by
        all assessment types.
        """

        return [
            (
                f"Static analyzer identified "
                f"{evidence.vulnerability_type}."
            ),
            (
                f"Location: {evidence.file}:"
                f"{evidence.line}"
            ),
            (
                f"Function: {evidence.function}"
            ),
            (
                f"Analyzer message: "
                f"{evidence.static_finding}"
            ),
        ]

    def _analyze_unsafe_eval(self, evidence):
        return SecurityAssessment(
            confirmed=True,
            confidence=0.90,
            vulnerability_type=evidence.vulnerability_type,
            severity=evidence.severity,
            root_cause=(
                "The code uses eval(), which dynamically evaluates "
                "a string as Python code."
            ),
            impact=(
                "If attacker-controlled input reaches eval(), "
                "arbitrary Python expressions may be executed."
            ),
            recommended_action=(
                "Remove eval() where possible and replace it with "
                "a constrained parsing or explicit dispatch mechanism."
            ),
            evidence_summary=self._base_evidence(evidence),
            limitations=[
                "Static analysis has not established whether the "
                "evaluated value is attacker-controlled."
            ],
        )

    def _analyze_unsafe_exec(self, evidence):
        return SecurityAssessment(
            confirmed=True,
            confidence=0.90,
            vulnerability_type=evidence.vulnerability_type,
            severity=evidence.severity,
            root_cause=(
                "The code uses exec(), which dynamically executes "
                "Python statements."
            ),
            impact=(
                "If attacker-controlled content reaches exec(), "
                "arbitrary Python code execution may be possible."
            ),
            recommended_action=(
                "Remove exec() and replace dynamic execution with "
                "explicit, constrained program logic."
            ),
            evidence_summary=self._base_evidence(evidence),
            limitations=[
                "Static analysis has not established whether the "
                "executed value originates from an untrusted source."
            ],
        )

    def _analyze_command_injection(self, evidence):
        return SecurityAssessment(
            confirmed=True,
            confidence=0.92,
            vulnerability_type=evidence.vulnerability_type,
            severity=evidence.severity,
            root_cause=(
                "The code invokes a command execution mechanism "
                "in a potentially shell-interpreted context."
            ),
            impact=(
                "Untrusted command content may allow unintended "
                "operating-system command execution."
            ),
            recommended_action=(
                "Avoid shell interpretation and use a safe argument "
                "list with explicit command boundaries."
            ),
            evidence_summary=self._base_evidence(evidence),
            limitations=[
                "The current static analyzer has not traced the "
                "input back to its original source."
            ],
        )

    def _analyze_unsafe_deserialization(self, evidence):
        return SecurityAssessment(
            confirmed=True,
            confidence=0.88,
            vulnerability_type=evidence.vulnerability_type,
            severity=evidence.severity,
            root_cause=(
                "The code uses a deserialization mechanism that "
                "may process data in an unsafe manner."
            ),
            impact=(
                "Processing attacker-controlled serialized data "
                "may result in unintended code execution or other "
                "security-impacting behavior."
            ),
            recommended_action=(
                "Use a safe deserialization mechanism appropriate "
                "for the expected data format and trust boundary."
            ),
            evidence_summary=self._base_evidence(evidence),
            limitations=[
                "The current analysis does not determine whether "
                "the serialized input is attacker-controlled."
            ],
        )

    def _analyze_hardcoded_credential(self, evidence):
        return SecurityAssessment(
            confirmed=True,
            confidence=0.82,
            vulnerability_type=evidence.vulnerability_type,
            severity=evidence.severity,
            root_cause=(
                "A string literal was assigned to a variable whose "
                "name suggests it may contain a credential or secret."
            ),
            impact=(
                "Credentials embedded in source code may be exposed "
                "through source repositories, logs, builds, or "
                "compiled/distributed artifacts."
            ),
            recommended_action=(
                "Move the credential to an appropriate secret or "
                "environment-variable mechanism."
            ),
            evidence_summary=self._base_evidence(evidence),
            limitations=[
                "The analyzer cannot determine whether the string "
                "is actually a valid credential.",
                "The current implementation does not perform "
                "secret-value validation.",
            ],
        )

    def _analyze_parse_error(self, evidence):
        return SecurityAssessment(
            confirmed=False,
            confidence=1.0,
            vulnerability_type=evidence.vulnerability_type,
            severity=evidence.severity,
            root_cause=(
                "The Python parser could not construct an AST "
                "for the affected file."
            ),
            impact=(
                "Static security analysis cannot reliably inspect "
                "the affected file until the syntax problem is resolved."
            ),
            recommended_action=(
                "Treat the parsing failure as an analysis limitation "
                "rather than as a confirmed vulnerability."
            ),
            evidence_summary=self._base_evidence(evidence),
            limitations=[
                "Security findings inside the unparseable file "
                "could not be analyzed."
            ],
        )

    def _generic_assessment(self, evidence):
        return SecurityAssessment(
            confirmed=False,
            confidence=0.50,
            vulnerability_type=evidence.vulnerability_type,
            severity=evidence.severity,
            root_cause=(
                "The current analyst does not yet have a specialized "
                "assessment rule for this finding type."
            ),
            impact=(
                "The potential security impact requires additional "
                "analysis."
            ),
            recommended_action=(
                "Route the finding to deeper analysis or the "
                "reasoning model."
            ),
            evidence_summary=self._base_evidence(evidence),
            limitations=[
                "No specialized analyst logic exists for this "
                "vulnerability type yet."
            ],
        )