"""
Feature Engineering: Extracts 15 Environment-Neutral Features from Tool Calls.
"""

import math
import re
from typing import Dict, Any, List

class FeatureExtractor:
    CATEGORY_MAPPING = {
        # Read operations
        "read_inbox": 0, "search_emails": 0, "get_file": 0, "read_channel": 0,
        "search_messages": 0, "check_balance": 0, "get_transaction_history": 0,
        "search_flights": 0, "search_hotels": 0,
        # Write operations
        "save_draft": 1, "update_file": 1, "create_event": 1,
        # Send / Communication operations
        "send_email": 2, "post_message": 2, "reply_thread": 2,
        # Pay / High-Impact operations
        "transfer_funds": 3, "reserve_booking": 3, "confirm_booking": 3, "delete_account": 3
    }

    def __init__(self):
        self.feature_names = [
            "tool_category",
            "bigram_prob",
            "trigram_prob",
            "cumulative_calls",
            "unseen_recipient_flag",
            "external_url_flag",
            "context_tainted_flag",
            "arg_string_entropy",
            "arg_length_zscore",
            "cross_domain_flag",
            "param_count",
            "repeated_call_rate",
            "read_to_write_ratio",
            "sensitive_param_present",
            "time_delta_normalized"
        ]

    def _calc_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        return -sum([p * math.log(p) / math.log(2.0) for p in prob])

    def extract(self, tool_name: str, args: Dict[str, Any], trace_history: List[Dict[str, Any]], is_tainted: bool = False) -> List[float]:
        # 1. Tool Category ID
        cat_id = float(self.CATEGORY_MAPPING.get(tool_name.lower(), 4)) # 4 = Other

        # 2. Sequential Bigram Transition
        prev_cat = 0.0
        if trace_history:
            prev_tool = trace_history[-1].get("tool", "")
            prev_cat = float(self.CATEGORY_MAPPING.get(prev_tool.lower(), 4))
        bigram_prob = 0.85 if prev_cat == 0.0 and cat_id in (0.0, 1.0) else 0.04

        # 3. Trigram Transition
        trigram_prob = 0.70 if len(trace_history) >= 2 else 0.50

        # 4. Cumulative Tool Calls
        cum_calls = float(len(trace_history) + 1)

        # 5. Unseen Recipient Flag
        arg_str = str(args).lower()
        unseen_recipient = 1.0 if ("@" in arg_str and "company.internal" not in arg_str) else 0.0

        # 6. External URL Flag
        has_url = 1.0 if any(u in arg_str for u in ["http://", "https://", "ftp://"]) else 0.0

        # 7. Context Tainted Flag
        taint = 1.0 if is_tainted else 0.0

        # 8. Argument Entropy
        entropy = min(self._calc_entropy(arg_str), 8.0)

        # 9. Length Z-Score estimate
        length_zscore = min(max((len(arg_str) - 80.0) / 45.0, -3.0), 5.0)

        # 10. Cross-Domain Flag
        cross_domain = 1.0 if (cat_id in (2.0, 3.0) and taint == 1.0) else 0.0

        # 11. Parameter Count
        param_count = float(len(args))

        # 12. Repeated Call Rate
        recent_names = [t.get("tool", "") for t in trace_history[-3:]]
        rep_rate = float(recent_names.count(tool_name)) / max(len(recent_names), 1)

        # 13. Read to Write Ratio
        read_count = sum(1 for t in trace_history if self.CATEGORY_MAPPING.get(t.get("tool", ""), 4) == 0)
        read_ratio = float(read_count) / max(cum_calls, 1.0)

        # 14. Sensitive Parameter Present (e.g. amount, token, password)
        has_sensitive = 1.0 if any(k in arg_str for k in ["amount", "password", "token", "balance", "credit"]) else 0.0

        # 15. Time Delta Normalized
        time_delta = 1.0

        return [
            cat_id, bigram_prob, trigram_prob, cum_calls, unseen_recipient,
            has_url, taint, entropy, length_zscore, cross_domain,
            param_count, rep_rate, read_ratio, has_sensitive, time_delta
        ]
