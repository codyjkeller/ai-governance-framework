# 🛡️ Enterprise AI Governance Framework (5-Layer Model)

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Architecture](https://img.shields.io/badge/Architecture-5--Layer_Security-orange)
![Policy-as-Code](https://img.shields.io/badge/Policy-YAML_Enforcement-green)

**A modular "Policy-as-Code" framework designed to allow regulated enterprises (CJIS, HIPAA, SOC 2) to adopt Generative AI while enforcing strict data controls.**

This repository implements a **Governance Proxy** that sits between users and LLMs (like OpenAI or Anthropic). It intercepts traffic to sanitize inputs (Layer 1) and validate outputs (Layer 5) based on a central YAML policy.

## 🏗️ The 5-Layer Architecture
This framework enforces security at every stage of the lifecycle:

1.  **Input Layer:** Sanitization of prompts to prevent PII leakage and Jailbreak attempts.
2.  **Boundary Layer:** Context window management and token budgeting.
3.  **Process Layer (RAG):** Strictly scoped retrieval from verified "Master Answer Banks."
4.  **Quality Layer:** Confidence scoring and citation verification.
5.  **Safety Layer:** Final output scanning for bias, toxicity, or training data leakage.

## 📂 Repository Contents

| Component | File | Description |
| :--- | :--- | :--- |
| **Orchestrator** | [`main.py`](main.py) | **Start Here.** A CLI simulation that runs the full governance pipeline (Input -> Mock LLM -> Output). |
| **Policy Engine** | [`policies/generative_ai_aup.yaml`](policies/generative_ai_aup.yaml) | **The Brain.** YAML definition of acceptable use, including PII rules and wildcard model allow-lists (e.g., `gpt-4*`). |
| **Input Guard** | [`guardrails/pii_scanner.py`](guardrails/pii_scanner.py) | **Layer 1:** Scans and redacts PII (SSN, Email, API Keys) using regex and heuristics *before* the LLM sees it. |
| **Output Guard** | [`guardrails/output_scanner.py`](guardrails/output_scanner.py) | **Layer 5:** Scans LLM responses for data leakage (secrets), hallucinated URLs, or toxic content. |

## 🧪 Demo Walkthrough

This repository includes a simulation (`main.py`) to demonstrate the governance logic in real-time.

### Step 1: Installation
```bash
pip install -r requirements.txt
