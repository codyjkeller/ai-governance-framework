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
    
    # 🛡️ EXPANDED PATTERN LIBRARY
    PATTERNS = {
        'SSN': r'\b\d{3}-\d{2}-\d{4}\b',
        'EMAIL': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'CREDIT_CARD': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
        
        # New Patterns Added
        'PHONE_US': r'\b(?:\+?1[-.]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
        'IP_ADDRESS': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'US_ZIP_CODE': r'\b\d{5}(?:-\d{4})?\b',
        
        # Heuristic for Street Addresses (e.g., "123 Main St")
        'STREET_ADDRESS': r'\b\d{1,5}\s+\w+(?:\s+\w+)*\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct)\b',
        
        'API_KEY': r'(?i)(api_key|access_token|secret)\s*[:=]\s*[a-zA-Z0-9_\-]{20,}'
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
            console.print(f"[red]❌ Critical Error: Policy file '{path}' not found.[/red]")
            return {}

    def is_model_allowed(self, requested_model):
        """
        Checks if the requested model ID matches the allow-list patterns.
        Supports wildcards (e.g., 'gpt-4*').
        """
        allowed_patterns = self.policy.get('global_settings', {}).get('allowed_model_families', [])
        
        for pattern in allowed_patterns:
            if fnmatch.fnmatch(requested_model, pattern):
                return True
        return False

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
            # Get rule from YAML (default to 'confidential' behavior if not found)
            # This allows new patterns to default to 'REDACT' without breaking the app
            rule = self.policy.get('data_rules', {}).get(pii_type.lower(), {
                'sensitivity': 'UNKNOWN', 'action': 'REDACT'
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
            console.print("[green]✅ Clean Payload. No PII detected.[/green]")
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
            console.print(Panel("[bold red]⛔ TRANSACTION BLOCKED BY POLICY[/bold red]\nRestricted data detected. Payload dropped.", border_style="red"))
        else:
            console.print(Panel("[bold yellow]⚠️  PAYLOAD MODIFIED[/bold yellow]\nSensitive data redacted. Forwarding sanitized prompt.", border_style="yellow"))

# --- DEMO RUNNER ---
if __name__ == "__main__":
    proxy = GovernanceProxy()

    print("\n--- TEST: Expanded Pattern Matching ---")
    
    # A realistic "noisy" prompt a user might paste
    complex_prompt = """
    Hi AI, I need help formatting this customer list for the CRM:
    
    1. John Doe - 555-0199 - 123 Maple Ave, Springfield
    2. Jane Smith - (415) 555-1234 - 456 Oak Dr, San Francisco
    3. Server Config: 192.168.1.55 connected to database.
    
    Please convert to JSON.
    """
    
    clean_prompt, status = proxy.scan_prompt(complex_prompt)
    
    if status == "SAFE":
        print(f"\n[Forwarding to LLM]:\n{clean_prompt}")
