import re
import yaml
import os
import fnmatch
import logging
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# Setup Rich Console for visual dashboards
console = Console()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [GOVERNANCE] - %(message)s')

class GovernanceProxy:
    """
    Enterprise AI Governance Layer.
    Acts as a middleware to sanitize inputs (Layer 1) and enforce policy (Layer 2)
    before data reaches external Model Providers.
    """
    
    # 🛡️ EXPANDED PATTERN LIBRARY (PII, HIPAA, SECRETS)
    PATTERNS = {
        # --- 1. GENERAL PII ---
        'SSN': r'\b\d{3}-\d{2}-\d{4}\b',
        'EMAIL': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'PHONE_US': r'\b(?:\+?1[-.]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
        'US_ZIP_CODE': r'\b\d{5}(?:-\d{4})?\b',
        
        # --- 2. FINANCIAL & ASSETS ---
        'CREDIT_CARD': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
        'VIN_NUMBER': r'\b(?![a-z])[A-HJ-NPR-Z0-9]{17}\b',  # 17-char Vehicle ID (No I, O, Q)
        
        # --- 3. INFRASTRUCTURE & SECRETS ---
        'IP_ADDRESS': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'AWS_ACCESS_KEY': r'\b(AKIA|ASIA)[0-9A-Z]{16}\b',   # AWS Key ID Pattern
        'PRIVATE_KEY_BLOCK': r'-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY-----',
        'API_KEY_GENERIC': r'(?i)(api_key|access_token|secret)\s*[:=]\s*[a-zA-Z0-9_\-]{20,}',

        # --- 4. HIPAA / MEDICAL ---
        'ICD10_CODE': r'\b[A-Z]\d{2}\.\d{1,3}\b',           # Medical Diagnosis (e.g., J01.90)
        'DEA_NUMBER': r'\b[A-Z]{2}\d{7}\b',                 # Doctor/Prescriber License ID
    }

    def __init__(self, policy_path="policies/generative_ai_aup.yaml"):
        self.policy = self._load_policy(policy_path)
        self.enforcement_mode = self.policy.get('global_settings', {}).get('enforcement_mode', 'blocking')

    def _load_policy(self, path):
        """Safely loads the AUP YAML file."""
        # Fallback logic if running from different directories
        if not os.path.exists(path):
            if os.path.exists("../" + path):
                path = "../" + path
            elif os.path.exists("generative_ai_aup.yaml"):
                path = "generative_ai_aup.yaml"
        
        try:
            with open(path, "r") as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            # Create a dummy policy in memory if file is missing to prevent crash
            console.print(f"[yellow]⚠️  Warning: Policy file '{path}' not found. Using default rules.[/yellow]")
            return {
                'global_settings': {'enforcement_mode': 'blocking'},
                'data_rules': {
                    'ssn': {'action': 'BLOCK', 'sensitivity': 'CRITICAL'},
                    'aws_access_key': {'action': 'BLOCK', 'sensitivity': 'CRITICAL'},
                    'icd10_code': {'action': 'REDACT', 'sensitivity': 'HIGH'},
                    'default': {'action': 'REDACT', 'sensitivity': 'UNKNOWN'}
                }
            }

    def scan_prompt(self, prompt_text):
        """
        Layer 1: Input Sanitization
        Scans prompt for PII patterns defined in the AUP.
        Returns: (sanitized_prompt, status_code)
        """
        console.rule("[bold blue]🛡️  AI Governance Proxy - Layer 1 Scan[/bold blue]")
        console.print(f"[dim]Analyzing Payload: {len(prompt_text)} chars[/dim]\n")

        violations = []
        modified_prompt = prompt_text
        blocked = False

        # Scan text against regex patterns
        for pii_type, pattern in self.PATTERNS.items():
            # Get rule from YAML (default to 'REDACT' behavior if not found)
            rule = self.policy.get('data_rules', {}).get(pii_type.lower(), {
                'sensitivity': 'HIGH', 'action': 'REDACT'
            })
            
            matches = re.findall(pattern, prompt_text, re.IGNORECASE)
            if matches:
                # Remove duplicates to clean up report
                unique_matches = list(set(matches))
                for m in unique_matches:
                    violations.append({
                        "type": pii_type,
                        "sensitivity": rule['sensitivity'],
                        "action": rule['action'],
                        "content": m
                    })
                    
                    # Apply Remediation
                    if rule['action'] == "BLOCK":
                        blocked = True
                    elif rule['action'] == "REDACT":
                        modified_prompt = modified_prompt.replace(m, f"[{pii_type}_REDACTED]")

        self._generate_report(violations, blocked)
        
        if blocked:
            return None, "BLOCKED"
        return modified_prompt, "SAFE"

    def _generate_report(self, violations, blocked):
        """Outputs a rich table summary of the scan."""
        if not violations:
            console.print("[green]✅ Clean Payload. No Sensitive Data detected.[/green]")
            return

        table = Table(title="⚠️  Governance Violations Detected")
        table.add_column("Data Type", style="cyan")
        table.add_column("Sensitivity", style="yellow")
        table.add_column("Policy Action", style="bold red")
        table.add_column("Content Found", style="dim")

        for v in violations:
            table.add_row(v['type'], v['sensitivity'], v['action'], v['content'])

        console.print(table)
        
        if blocked:
            console.print(Panel("[bold red]⛔ TRANSACTION BLOCKED BY POLICY[/bold red]\nCritical infrastructure or Identity data detected.", border_style="red"))
        else:
            console.print(Panel("[bold yellow]⚠️  PAYLOAD MODIFIED[/bold yellow]\nSensitive data redacted. Forwarding sanitized prompt to LLM.", border_style="yellow"))

# --- DEMO RUNNER ---
if __name__ == "__main__":
    proxy = GovernanceProxy()

    print("\n--- TEST: Multi-Domain Scanner (HIPAA, Secrets, PII) ---")
    
    # A realistic "dangerous" prompt mixing Medical, Infra, and PII
    complex_prompt = """
    Summarize this patient note for Dr. Smith (DEA: AB1234567):
    Patient diagnosed with J01.90 (Acute sinusitis).
    
    Also, we migrated the database.
    AWS Creds: AKIAIOSFODNN7EXAMPLE
    Server IP: 192.168.1.55
    """
    
    clean_prompt, status = proxy.scan_prompt(complex_prompt)
    
    if status == "SAFE":
        print(f"\n[Forwarding to LLM]:\n{clean_prompt}")
