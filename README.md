# 🛡️ AI Security Toolkit

<div align="center">

![AI Security](https://img.shields.io/badge/AI-Security-red?style=for-the-badge&logo=shield)
![Python](https://img.shields.io/badge/Python-3.9+-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

**A comprehensive toolkit for AI/LLM security research, red teaming, and vulnerability assessment.**

*For ethical security researchers, red teams, and AI safety engineers.*

</div>

---

## ⚠️ Disclaimer

> This toolkit is intended **strictly for authorized security testing, academic research, and defensive purposes only**. All tools must be used only on systems you own or have explicit written permission to test. Misuse of these tools against production systems without authorization is illegal and unethical. The authors assume no liability for unauthorized or malicious use.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Attack Categories](#attack-categories)
- [Tools](#tools)
- [Payloads Library](#payloads-library)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Benchmarks](#benchmarks)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [References](#references)

---

## Overview

AI Security Toolkit covers the full spectrum of known LLM and AI model attack surfaces:

| Category | Description | Severity |
|---|---|---|
| Prompt Injection | Hijacking model instructions | 🔴 Critical |
| Jailbreaking | Bypassing safety filters | 🔴 Critical |
| Adversarial Inputs | Perturbing inputs to mislead models | 🟠 High |
| Model Extraction | Stealing model behavior via queries | 🟠 High |
| Data Poisoning | Corrupting training data | 🔴 Critical |
| Inference Attacks | Leaking training data via outputs | 🟡 Medium |
| Indirect Injection | Injecting via external data sources | 🔴 Critical |
| Denial of Service | Overloading or crashing AI systems | 🟡 Medium |
| Supply Chain | Compromising model weights/pipelines | 🔴 Critical |

---

## Attack Categories

### 1. 🎯 Prompt Injection
Injecting malicious instructions into prompts to override system behavior, exfiltrate data, or manipulate outputs.

### 2. 🔓 Jailbreaking & Safety Filter Bypass
Testing robustness of safety guardrails through role-play, encoding tricks, and indirect framing.

### 3. 🌀 Adversarial Text Attacks
Perturbing inputs using character substitution, Unicode homoglyphs, and synonym swapping to fool classifiers.

### 4. 🕵️ Model Extraction
Reconstructing model behavior through systematic querying — membership inference and decision boundary probing.

### 5. ☣️ Data Poisoning Detection
Identifying backdoor triggers and poisoned training samples in fine-tuned models.

### 6. 🔍 Training Data Inference
Extracting memorized training data through targeted prompting and canary recovery.

### 7. 🌐 Indirect Prompt Injection
Injecting payloads via external documents, web pages, emails read by AI agents.

### 8. 🤖 Multi-Agent Attack Simulation
Testing trust chains and privilege escalation in LLM-powered multi-agent systems.

---

## Tools

```
ai-security-toolkit/
├── tools/
│   ├── prompt_injection/       # Prompt injection test suite
│   ├── adversarial/            # Adversarial text generation
│   ├── model_extraction/       # Model stealing via black-box queries
│   ├── jailbreak_detector/     # Automated jailbreak detection & testing
│   ├── fuzzer/                 # LLM fuzzing engine
│   ├── data_poisoning/         # Backdoor detection tools
│   └── inference_attack/       # Training data extraction
├── payloads/                   # Curated payload libraries
├── benchmarks/                 # Evaluation harness
├── docs/                       # Deep-dive documentation
└── reports/                    # Report templates
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/ai-security-toolkit.git
cd ai-security-toolkit

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Optional: Install dev dependencies
pip install -r requirements-dev.txt
```

### Environment Setup

```bash
cp .env.example .env
# Edit .env and add your API keys for the models you're testing
```

---

## Quick Start

### Run Prompt Injection Tests
```bash
python tools/prompt_injection/injector.py \
  --target openai \
  --model gpt-4 \
  --payload-file payloads/prompt_injections.json \
  --output reports/injection_report.json
```

### Run Jailbreak Detection
```bash
python tools/jailbreak_detector/detector.py \
  --model claude-3 \
  --mode scan \
  --payload-set standard
```

### Run Full Adversarial Suite
```bash
python benchmarks/eval_suite.py \
  --target-model gpt-4o \
  --attack-types all \
  --report-format html
```

### Fuzz an LLM Endpoint
```bash
python tools/fuzzer/llm_fuzzer.py \
  --endpoint http://localhost:8000/v1/chat \
  --iterations 500 \
  --strategy grammar
```

---

## Benchmarks

We track the following metrics:

- **ASR** — Attack Success Rate
- **bypass_rate** — Safety filter bypass rate  
- **extraction_fidelity** — Model extraction accuracy
- **detection_evasion** — % attacks evading detection

See [`benchmarks/README.md`](benchmarks/README.md) for full methodology.

---

## Documentation

| Doc | Description |
|---|---|
| [Attack Techniques](docs/attack-techniques.md) | Deep dive into each attack class |
| [Defense Strategies](docs/defense-strategies.md) | Mitigations and hardening guide |
| [Red Team Playbook](docs/red-team-playbook.md) | Structured red teaming workflow |
| [Responsible Disclosure](docs/responsible-disclosure.md) | How to report vulnerabilities |
| [API Reference](docs/api-reference.md) | Tool API documentation |

---

## Contributing

We welcome contributions from the security research community! Please read [CONTRIBUTING.md](.github/CONTRIBUTING.md) before submitting PRs.

Areas we especially need help with:
- New payload patterns
- Defenses and detection methods
- Multi-modal (image + text) attack vectors
- Benchmark datasets

---

## References & Research

- [OWASP Top 10 for LLMs](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Greshake et al. — Indirect Prompt Injection (2023)](https://arxiv.org/abs/2302.12173)
- [Perez & Ribeiro — Ignore Previous Prompt (2022)](https://arxiv.org/abs/2211.09527)
- [Carlini et al. — Extracting Training Data (2021)](https://arxiv.org/abs/2012.07805)
- [Wallace et al. — Universal Adversarial Triggers (2019)](https://arxiv.org/abs/1908.07125)
- [NIST AI RMF](https://www.nist.gov/system/files/documents/2023/01/26/AI%20RMF%201.0.pdf)

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">
<b>Built for the AI Security Research Community 🔐</b><br/>
Star ⭐ this repo if it helped your research!
</div>
