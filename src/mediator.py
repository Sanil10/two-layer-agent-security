"""
Layer 1: Rule-Based Declarative Tool-Call Mediator.
Enforces YAML policies, parameter limits, and taint-gated execution.
"""

import os
import yaml
from typing import Dict, Any, Tuple

class PolicyMediator:
    def __init__(self, rules_dir: str = "rules"):
        self.rules_dir = rules_dir
        self.rules = {}
        self._load_rules()

    def _load_rules(self):
        if not os.path.exists(self.rules_dir):
            return
        for f in os.listdir(self.rules_dir):
            if f.endswith(".yaml") or f.endswith(".yml"):
                path = os.path.join(self.rules_dir, f)
                with open(path, "r", encoding="utf-8") as yf:
                    data = yaml.safe_load(yf)
                    env = data.get("environment", f.split("_")[0])
                    self.rules[env] = data

    def evaluate(self, env_name: str, tool_name: str, args: Dict[str, Any], is_tainted: bool = False) -> Tuple[str, str]:
        """
        Returns: (Decision, Reason)
        Decisions: 'ALLOW', 'BLOCK', 'SIMULATED_CONFIRMATION'
        """
        env_spec = self.rules.get(env_name.lower())
        if not env_spec:
            # Default fail-safe if env not explicitly defined
            return "ALLOW", "No specific policy for environment; permitted by default."

        tools_spec = env_spec.get("tools", {})
        tool_rule = tools_spec.get(tool_name)

        if not tool_rule:
            return "ALLOW", f"Tool '{tool_name}' has no restrictive rules."

        action = tool_rule.get("action", "allow")
        if action == "allow":
            return "ALLOW", f"Tool '{tool_name}' is explicitly allowed."

        if action == "block":
            return "BLOCK", f"Tool '{tool_name}' is explicitly prohibited."

        # Conditional checks
        for r in tool_rule.get("rules", []):
            check_type = r.get("check")

            # Max Amount Check
            if check_type in ("max_amount", "max_booking_cost"):
                limit = r.get("limit", float("inf"))
                amount = float(args.get("amount", args.get("cost", 0.0)))
                if amount > limit:
                    return "BLOCK", r.get("error_message", f"Amount {amount} exceeds limit {limit}")

            # Payee Whitelist
            elif check_type == "payee_whitelist":
                allowed = [p.lower() for p in r.get("allowed_payees", [])]
                payee = str(args.get("recipient", args.get("payee", ""))).lower()
                if payee and not any(a in payee for a in allowed):
                    return "BLOCK", r.get("error_message", f"Payee '{payee}' not authorized")

            # Domain Whitelist
            elif check_type == "domain_whitelist":
                allowed_domains = r.get("allowed_domains", [])
                recipient = str(args.get("to", args.get("recipient", ""))).lower()
                if recipient and "@" in recipient:
                    domain = recipient.split("@")[-1]
                    if not any(d in domain for d in allowed_domains):
                        return "BLOCK", r.get("error_message", f"Domain '{domain}' not in whitelist")

            # External URL Exfiltration
            elif check_type == "no_external_url_exfiltration":
                patterns = r.get("disallow_patterns", ["http://", "https://"])
                body = str(args).lower()
                if any(p in body for p in patterns):
                    return "BLOCK", r.get("error_message", "External URL detected in payload")

            # Tainted Context Gating
            elif check_type == "tainted_context_gating":
                if is_tainted:
                    on_viol = r.get("on_violation", "simulated_confirmation")
                    decision = "SIMULATED_CONFIRMATION" if on_viol == "simulated_confirmation" else "BLOCK"
                    return decision, r.get("error_message", "Sensitive tool invoked from tainted context")

        return "ALLOW", "All Layer 1 declarative constraints satisfied."
