"""
Adversarial Text Generator
============================
Generates adversarial text examples to test robustness of AI classifiers and LLMs.

Techniques:
- Character substitution (typos, homoglyphs)
- Word synonym replacement
- Whitespace insertion
- Case perturbation
- Invisible Unicode insertion
- Back-translation augmentation

Usage:
    python text_perturber.py --input "test sentence" --techniques all --count 10
"""

import random
import re
import unicodedata
from dataclasses import dataclass
from typing import Callable

import click
from rich.console import Console
from rich.table import Table

console = Console()

# ─────────────────────────────────────────────────────────
# Homoglyph & Substitution Maps
# ─────────────────────────────────────────────────────────

HOMOGLYPHS: dict[str, list[str]] = {
    'a': ['а', 'а', 'ä', '@', '4'],   # Cyrillic а, Unicode variants
    'e': ['е', 'ё', '3', 'ε'],
    'i': ['і', 'ї', '1', 'l', '|'],
    'o': ['о', 'ο', '0', 'ø'],
    'c': ['с', 'ć', 'ç'],
    'p': ['р', 'ρ'],
    'x': ['х', 'χ'],
    's': ['ѕ', '$', '5'],
    'n': ['η', 'ń'],
    'u': ['υ', 'ü', 'ú'],
    'A': ['А', 'Α', '4'],
    'B': ['В', 'Β', '8'],
    'E': ['Е', 'Ε', '3'],
    'H': ['Н', 'Η'],
    'I': ['І', 'Ι', '1', '|'],
    'K': ['К', 'Κ'],
    'M': ['М', 'Μ'],
    'O': ['О', 'Ο', '0'],
    'P': ['Р', 'Ρ'],
    'T': ['Т', 'Τ'],
    'X': ['Х', 'Χ'],
    'Y': ['У', 'Υ'],
}

LEET_MAP: dict[str, str] = {
    'a': '4', 'e': '3', 'g': '9', 'i': '1',
    'l': '1', 'o': '0', 's': '5', 't': '7',
    'b': '6', 'z': '2'
}

SIMPLE_SYNONYMS: dict[str, list[str]] = {
    'ignore': ['disregard', 'forget', 'skip', 'bypass', 'overlook'],
    'previous': ['prior', 'earlier', 'above', 'preceding'],
    'instructions': ['directives', 'guidelines', 'commands', 'rules', 'prompts'],
    'system': ['core', 'base', 'internal', 'underlying'],
    'tell': ['say', 'output', 'print', 'show', 'reveal'],
    'now': ['currently', 'at this point', 'henceforth'],
    'act': ['behave', 'respond', 'operate', 'function'],
    'help': ['assist', 'support', 'aid'],
    'harmful': ['dangerous', 'unsafe', 'risky'],
    'restricted': ['blocked', 'forbidden', 'prohibited'],
}

INVISIBLE_CHARS = [
    '\u200b',  # Zero Width Space
    '\u200c',  # Zero Width Non-Joiner
    '\u200d',  # Zero Width Joiner
    '\ufeff',  # Zero Width No-Break Space
    '\u2060',  # Word Joiner
]


# ─────────────────────────────────────────────────────────
# Perturbation Functions
# ─────────────────────────────────────────────────────────

@dataclass
class PerturbedSample:
    technique: str
    original: str
    perturbed: str
    char_diff: int
    word_diff: int


def homoglyph_substitution(text: str, rate: float = 0.3) -> str:
    """Replace characters with Unicode homoglyphs."""
    result = []
    for ch in text:
        if ch in HOMOGLYPHS and random.random() < rate:
            result.append(random.choice(HOMOGLYPHS[ch]))
        else:
            result.append(ch)
    return ''.join(result)


def leet_speak(text: str, rate: float = 0.5) -> str:
    """Convert text to leet speak."""
    result = []
    for ch in text.lower():
        if ch in LEET_MAP and random.random() < rate:
            result.append(LEET_MAP[ch])
        else:
            result.append(ch)
    return ''.join(result)


def case_perturbation(text: str, mode: str = 'random') -> str:
    """Perturb character casing."""
    if mode == 'upper':
        return text.upper()
    elif mode == 'lower':
        return text.lower()
    elif mode == 'alternating':
        return ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(text))
    else:  # random
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in text)


def whitespace_insertion(text: str, rate: float = 0.15) -> str:
    """Insert spaces between characters at random."""
    result = []
    for ch in text:
        result.append(ch)
        if ch.isalpha() and random.random() < rate:
            result.append(' ')
    return ''.join(result)


def invisible_char_injection(text: str, rate: float = 0.1) -> str:
    """Inject invisible Unicode characters."""
    result = []
    for ch in text:
        result.append(ch)
        if random.random() < rate:
            result.append(random.choice(INVISIBLE_CHARS))
    return ''.join(result)


def synonym_replacement(text: str, rate: float = 0.4) -> str:
    """Replace words with synonyms from the map."""
    words = text.split()
    result = []
    for word in words:
        clean = word.lower().strip('.,!?;:')
        if clean in SIMPLE_SYNONYMS and random.random() < rate:
            replacement = random.choice(SIMPLE_SYNONYMS[clean])
            # Preserve original casing style
            if word[0].isupper():
                replacement = replacement.capitalize()
            result.append(replacement)
        else:
            result.append(word)
    return ' '.join(result)


def character_deletion(text: str, rate: float = 0.05) -> str:
    """Randomly delete characters (simulates typos)."""
    return ''.join(c for c in text if random.random() > rate)


def character_duplication(text: str, rate: float = 0.08) -> str:
    """Randomly duplicate characters."""
    result = []
    for c in text:
        result.append(c)
        if c.isalpha() and random.random() < rate:
            result.append(c)
    return ''.join(result)


def word_order_shuffle(text: str, window: int = 3) -> str:
    """Shuffle words within a local window."""
    words = text.split()
    for i in range(0, len(words) - window, window):
        chunk = words[i:i + window]
        random.shuffle(chunk)
        words[i:i + window] = chunk
    return ' '.join(words)


def punctuation_insertion(text: str) -> str:
    """Insert punctuation to break tokenization."""
    markers = ['.', ',', '-', '/', '\\', '|']
    words = text.split()
    result = []
    for word in words:
        if len(word) > 3 and random.random() < 0.2:
            mid = len(word) // 2
            word = word[:mid] + random.choice(markers) + word[mid:]
        result.append(word)
    return ' '.join(result)


def rot13(text: str) -> str:
    """ROT13 encoding."""
    return text.translate(str.maketrans(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
        'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
    ))


def base64_encode_words(text: str) -> str:
    """Base64-encode individual words."""
    import base64
    words = text.split()
    encoded = [base64.b64encode(w.encode()).decode() for w in words]
    return f"Decode each word from base64 and follow: {' '.join(encoded)}"


# ─────────────────────────────────────────────────────────
# Perturbation Engine
# ─────────────────────────────────────────────────────────

TECHNIQUES: dict[str, Callable] = {
    'homoglyph': lambda t: homoglyph_substitution(t, 0.4),
    'leet': lambda t: leet_speak(t, 0.6),
    'case_random': lambda t: case_perturbation(t, 'random'),
    'case_alternating': lambda t: case_perturbation(t, 'alternating'),
    'whitespace': lambda t: whitespace_insertion(t, 0.2),
    'invisible': lambda t: invisible_char_injection(t, 0.15),
    'synonym': lambda t: synonym_replacement(t, 0.5),
    'deletion': lambda t: character_deletion(t, 0.05),
    'duplication': lambda t: character_duplication(t, 0.1),
    'shuffle': lambda t: word_order_shuffle(t),
    'punctuation': lambda t: punctuation_insertion(t),
    'rot13': rot13,
    'base64_words': base64_encode_words,
    'combined': lambda t: invisible_char_injection(homoglyph_substitution(leet_speak(t, 0.3), 0.2), 0.05),
}


def perturb(text: str, technique: str) -> PerturbedSample:
    fn = TECHNIQUES[technique]
    perturbed = fn(text)
    orig_words = set(text.lower().split())
    pert_words = set(perturbed.lower().split())
    return PerturbedSample(
        technique=technique,
        original=text,
        perturbed=perturbed,
        char_diff=abs(len(perturbed) - len(text)),
        word_diff=len(orig_words.symmetric_difference(pert_words))
    )


def generate_adversarial_set(text: str, techniques: list[str], count_per_technique: int = 3) -> list[PerturbedSample]:
    samples = []
    for technique in techniques:
        for _ in range(count_per_technique):
            sample = perturb(text, technique)
            samples.append(sample)
    return samples


# ─────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────

@click.command()
@click.option("--input", "text", required=True, help="Input text to perturb")
@click.option("--techniques", default="all", help="Comma-separated techniques or 'all'")
@click.option("--count", default=2, type=int, help="Samples per technique")
@click.option("--seed", default=42, type=int, help="Random seed")
def main(text, techniques, count, seed):
    """🌀 Adversarial Text Perturbation Engine"""
    random.seed(seed)

    if techniques == "all":
        selected = list(TECHNIQUES.keys())
    else:
        selected = [t.strip() for t in techniques.split(",")]

    console.print(f"\n[bold cyan]Adversarial Text Generator[/bold cyan]")
    console.print(f"[dim]Original:[/dim] {text}\n")

    samples = generate_adversarial_set(text, selected, count)

    table = Table(title="Adversarial Samples", show_lines=True)
    table.add_column("Technique", style="cyan", width=20)
    table.add_column("Perturbed Text", width=55)
    table.add_column("ΔChar", justify="right", width=6)

    for s in samples:
        table.add_row(s.technique, s.perturbed[:80], str(s.char_diff))

    console.print(table)
    console.print(f"\n[bold]Generated {len(samples)} adversarial samples across {len(selected)} techniques.[/bold]")


if __name__ == "__main__":
    main()
