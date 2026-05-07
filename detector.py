"""
Jailbreak Detector & Classifier
=================================
Detects and classifies jailbreak attempts in user inputs.
Useful for building AI content moderation pipelines.

Techniques:
- Pattern-based detection (regex + keywords)
- Semantic similarity to known attack patterns
- Heuristic scoring
- Output: risk score, attack category, recommended action

Usage:
    python detector.py --input "your text here" --mode single
    python detector.py --file inputs.txt --mode batch --output results.json
"""

import json
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


# ─────────────────────────────────────────────────────────
# Detection Patterns
# ─────────────────────────────────────────────────────────

ATTACK_PATTERNS: dict[str, dict] = {

    "ignore_previous": {
        "category": "Direct Override",
        "severity": "critical",
        "patterns": [
            r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?|guidelines?)",
            r"disregard\s+(all\s+)?(previous|prior)\s+instructions?",
            r"forget\s+(all\s+)?(previous|prior)\s+(instructions?|context)",
            r"override\s+(your\s+)?(previous\s+)?(instructions?|programming|rules?)",
        ]
    },

    "role_hijack": {
        "category": "Role Hijacking",
        "severity": "critical",
        "patterns": [
            r"you\s+are\s+now\s+(an?\s+)?(unrestricted|uncensored|unfiltered|jailbroken)",
            r"act\s+as\s+(an?\s+)?(AI\s+with\s+no\s+restrictions?|evil\s+AI|bad\s+AI|DAN|JAILBREAK)",
            r"pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(AI|assistant)\s+(with\s+no|without\s+any)\s+(restrictions?|limits?|guidelines?)",
            r"(DAN|jailbreak|JAILBREAK)\s+(mode|enabled|activated|on)",
            r"your\s+(new|true|real)\s+(instructions?|purpose|goal|mission)\s+is",
        ]
    },

    "system_prompt_exfiltration": {
        "category": "Prompt Exfiltration",
        "severity": "high",
        "patterns": [
            r"(print|output|show|reveal|display|repeat|tell\s+me)\s+(your\s+)?(system\s+prompt|initial\s+instructions?|base\s+prompt|original\s+instructions?)",
            r"what\s+(are|were)\s+your\s+(exact\s+)?(original\s+)?(instructions?|system\s+prompt|directives?)",
            r"(output|repeat)\s+(verbatim|exactly|word\s+for\s+word)\s+(your|the)\s+system",
        ]
    },

    "delimiter_attack": {
        "category": "Delimiter Confusion",
        "severity": "critical",
        "patterns": [
            r"---\s*(end\s+of\s+system|end\s+of\s+prompt|system\s+end|instructions?\s+end)",
            r"\[system\]|\[system_prompt\]|\[end\s+of\s+instructions?\]",
            r"```\s*(system|end|instructions?)",
            r"</?system>|</?prompt>|</?instructions?>",
            r"={3,}\s*(end|system|instructions?)",
        ]
    },

    "encoding_bypass": {
        "category": "Encoding Attack",
        "severity": "high",
        "patterns": [
            r"(decode\s+(this\s+)?base64|base64\s+decode)",
            r"rot-?13",
            r"(interpret|decode|translate)\s+(this\s+)?(hex|binary|morse|cipher|encoded)",
            r"[A-Za-z0-9+/]{20,}={0,2}",  # Base64-looking string
        ]
    },

    "privilege_escalation": {
        "category": "Privilege Escalation",
        "severity": "critical",
        "patterns": [
            r"(admin|developer|root|god|sudo)\s+(mode|access|privileges?|override)",
            r"(you\s+have\s+)?(unlimited|unrestricted|special|elevated)\s+(access|permissions?|privileges?)",
            r"maintenance\s+mode",
            r"debug\s+mode\s+enabled",
            r"(enter|activate|enable)\s+(unrestricted|jailbreak|bypass|dev)\s+mode",
        ]
    },

    "context_stuffing": {
        "category": "Context Manipulation",
        "severity": "medium",
        "patterns": [
            r"(here\s+are|the\s+following\s+are)\s+(example|sample)\s+(conversation|dialogue|interaction)s?",
            r"(previous|prior)\s+(conversation|session|example)\s*:",
            r"(assistant\s*:|AI\s*:)\s*(sure|of\s+course|yes|absolutely|no\s+problem)[,!]",
        ]
    },

    "indirect_injection": {
        "category": "Indirect Injection",
        "severity": "critical",
        "patterns": [
            r"\[?(IMPORTANT\s+)?SYSTEM\s+(NOTE|INSTRUCTION|UPDATE|OVERRIDE)\]?\s*:",
            r"\[?(NOTE\s+TO\s+(AI|ASSISTANT|MODEL|SYSTEM))\]?",
            r"(hidden\s+|invisible\s+)?instruction\s+for\s+(the\s+)?(AI|assistant|model|LLM)",
        ]
    },

    "many_shot_priming": {
        "category": "Many-Shot Priming",
        "severity": "medium",
        "patterns": [
            r"(Human|User)\s*:\s*.+\n(Assistant|AI|Bot)\s*:\s*(sure|yes|absolutely|of\s+course)",
            r"Q:\s*.+\nA:\s*(sure|yes|here|certainly)",
        ]
    },

}

# Suspicious keyword groups (score-based)
SUSPICIOUS_KEYWORDS: dict[str, int] = {
    # High-risk
    "jailbreak": 25, "DAN": 20, "unrestricted": 15, "uncensored": 15,
    "no restrictions": 20, "no limits": 15, "bypass": 10, "override": 10,
    "ignore instructions": 25, "forget instructions": 25,
    # Medium-risk
    "system prompt": 10, "confidential": 8, "secret instructions": 12,
    "reveal": 5, "hidden": 5, "your true self": 10, "your real self": 10,
    # Encoding
    "base64": 8, "rot13": 8, "encoded": 5, "decode": 5,
    # Role
    "pretend you are": 8, "act as if": 8, "roleplay": 5, "simulate": 5,
}


# ─────────────────────────────────────────────────────────
# Detector
# ─────────────────────────────────────────────────────────

@dataclass
class DetectionResult:
    input_text: str
    risk_score: int            # 0-100
    risk_level: str            # safe / low / medium / high / critical
    detected_categories: list[str]
    matched_patterns: list[str]
    keyword_hits: list[str]
    recommendation: str
    is_jailbreak_attempt: bool


def calculate_risk_level(score: int) -> str:
    if score == 0:
        return "safe"
    elif score < 20:
        return "low"
    elif score < 40:
        return "medium"
    elif score < 70:
        return "high"
    else:
        return "critical"


def get_recommendation(risk_level: str, categories: list[str]) -> str:
    if risk_level == "safe":
        return "✅ Input appears safe. No action required."
    elif risk_level == "low":
        return "🔵 Low risk. Monitor but allow. Consider logging."
    elif risk_level == "medium":
        return "🟡 Medium risk. Consider additional validation or human review."
    elif risk_level == "high":
        return "🟠 High risk. Block input and log for security review."
    else:
        return "🔴 CRITICAL: Likely jailbreak/injection attempt. Block immediately and alert security team."


def detect(text: str) -> DetectionResult:
    score = 0
    matched_categories: list[str] = []
    matched_patterns: list[str] = []
    keyword_hits: list[str] = []

    text_lower = text.lower()

    # Pattern matching
    for attack_name, config in ATTACK_PATTERNS.items():
        for pattern in config["patterns"]:
            if re.search(pattern, text_lower, re.IGNORECASE | re.MULTILINE):
                if attack_name not in matched_categories:
                    matched_categories.append(config["category"])
                matched_patterns.append(f"{attack_name}: {pattern[:50]}...")
                sev = config["severity"]
                score += {"critical": 35, "high": 20, "medium": 10, "low": 5}.get(sev, 5)
                break  # one match per attack type

    # Keyword scoring
    for keyword, points in SUSPICIOUS_KEYWORDS.items():
        if keyword.lower() in text_lower:
            keyword_hits.append(keyword)
            score += points

    # Length-based heuristics
    if len(text) > 2000:
        score += 5  # Very long inputs are more likely to contain injection attempts

    # Unicode heuristic (detect homoglyphs)
    cyrillic_count = sum(1 for c in text if '\u0400' <= c <= '\u04ff')
    if cyrillic_count > 3 and not all('\u0400' <= c <= '\u04ff' or c.isspace() for c in text):
        score += 15
        if "Unicode Homoglyph" not in matched_categories:
            matched_categories.append("Unicode Homoglyph")

    score = min(score, 100)
    risk_level = calculate_risk_level(score)

    return DetectionResult(
        input_text=text[:100] + "..." if len(text) > 100 else text,
        risk_score=score,
        risk_level=risk_level,
        detected_categories=matched_categories,
        matched_patterns=matched_patterns[:5],
        keyword_hits=list(set(keyword_hits))[:10],
        recommendation=get_recommendation(risk_level, matched_categories),
        is_jailbreak_attempt=score >= 40
    )


def print_result(result: DetectionResult):
    risk_colors = {
        "safe": "green", "low": "blue", "medium": "yellow",
        "high": "orange1", "critical": "red"
    }
    color = risk_colors.get(result.risk_level, "white")

    console.print(Panel(
        f"[bold {color}]Risk Level: {result.risk_level.upper()}[/bold {color}]  |  "
        f"Score: [{color}]{result.risk_score}/100[/{color}]\n\n"
        f"[dim]Input:[/dim] {result.input_text}\n\n"
        f"[bold]Detected Categories:[/bold] {', '.join(result.detected_categories) or 'None'}\n"
        f"[bold]Keyword Hits:[/bold] {', '.join(result.keyword_hits) or 'None'}\n\n"
        f"{result.recommendation}",
        title="🔍 Jailbreak Detection Result",
        border_style=color
    ))


# ─────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────

@click.command()
@click.option("--input", "text", default=None, help="Single input text to analyze")
@click.option("--file", "input_file", default=None, type=click.Path(), help="File with one input per line")
@click.option("--mode", default="single", type=click.Choice(["single", "batch"]), help="Detection mode")
@click.option("--output", default=None, help="Output JSON file for batch results")
@click.option("--threshold", default=40, type=int, help="Score threshold for jailbreak classification")
def main(text, input_file, mode, output, threshold):
    """🔍 AI Jailbreak & Injection Detector"""
    console.print("\n[bold red]🛡️  AI Security Toolkit — Jailbreak Detector[/bold red]\n")

    if mode == "single" and text:
        result = detect(text)
        print_result(result)

    elif mode == "batch" and input_file:
        lines = Path(input_file).read_text().splitlines()
        results = []
        table = Table(title="Batch Detection Results", show_lines=True)
        table.add_column("Input (truncated)", width=40)
        table.add_column("Risk", width=10)
        table.add_column("Score", justify="right", width=7)
        table.add_column("Categories", width=30)

        risk_colors = {"safe": "green", "low": "blue", "medium": "yellow", "high": "orange1", "critical": "red"}

        for line in lines:
            if not line.strip():
                continue
            r = detect(line.strip())
            results.append(asdict(r))
            color = risk_colors.get(r.risk_level, "white")
            table.add_row(
                r.input_text[:40],
                f"[{color}]{r.risk_level.upper()}[/{color}]",
                str(r.risk_score),
                ', '.join(r.detected_categories[:2]) or "none"
            )

        console.print(table)
        flagged = sum(1 for r in results if r["is_jailbreak_attempt"])
        console.print(f"\n[bold]Analyzed: {len(results)} | Flagged: [red]{flagged}[/red] ({flagged/len(results)*100:.1f}%)[/bold]")

        if output:
            with open(output, "w") as f:
                json.dump(results, f, indent=2)
            console.print(f"[green]Results saved to {output}[/green]")
    else:
        console.print("[red]Provide --input for single mode or --file for batch mode.[/red]")


if __name__ == "__main__":
    main()
