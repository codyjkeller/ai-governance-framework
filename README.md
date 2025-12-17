# Enterprise AI Governance Framework (5-Layer Model)

## 📌 Overview
This repository contains the architectural patterns and "Policy-as-Code" templates for the **5-Layer AI Governance Model**. This framework is designed to allow regulated enterprises (CJIS, HIPAA, SOC 2) to adopt Generative AI (LLMs) while maintaining strict data control.

## 🏗️ The 5-Layer Architecture
This model enforces security at every stage of the LLM interaction lifecycle:

1.  **Input Layer:** Sanitization of prompts to prevent PII leakage and Jailbreak attempts.
2.  **Boundary Layer:** Context window management and token budgeting.
3.  **Process Layer (RAG):** Strictly scoped retrieval from verified "Master Answer Banks" (no hallucination).
4.  **Quality Layer:** Confidence scoring and citation verification.
5.  **Safety Layer:** Final output scanning for bias, toxicity, or data leakage.

## 📂 Repository Contents

| Component | File | Description |
| :--- | :--- | :--- |
| **Policy Config** | [`/policies/generative_ai_aup.yaml`](policies/generative_ai_aup.yaml) | YAML definition of the Acceptable Use Policy, including model allow-lists and data classification rules. |
| **Safety Logic** | [`/guardrails/pii_scanner.py`](guardrails/pii_scanner.py) | Python module for the **Input/Safety Layers**. Scans payloads for PII (SSN, Credit Cards, API Keys) before processing. |
| **Architecture** | [`/diagrams/governance_flow.mermaid`](diagrams/governance_flow.mermaid) | Visual data flow diagram illustrating where the governance proxy sits between the User and the LLM. |

## 🚀 Integration Logic
These templates are designed to be integrated into an API Gateway or Middleware (e.g., LangChain, LibreChat) to act as a **Governance Proxy**.

**Example Logic Flow:**
1.  **User sends prompt:** *"Analyze this customer data..."*
2.  **Proxy intercepts:** Runs `pii_scanner.py`.
3.  **Check:** If PII detected $\rightarrow$ Redact or Block based on `generative_ai_aup.yaml`.
4.  **Forward:** Only clean data is sent to the Model Provider (OpenAI/Anthropic).

---
*Maintained by [Cody Keller](https://github.com/codyjkeller)*
