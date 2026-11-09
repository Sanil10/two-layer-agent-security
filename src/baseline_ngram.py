"""
Sequential n-gram Markov Transition Baseline for Anomaly Detection.
Tracks bigram and trigram tool category transition probabilities.
"""

from collections import defaultdict
from typing import List, Dict, Any

class NGramDetector:
    def __init__(self, threshold: float = 0.05):
        self.threshold = threshold
        self.bigram_counts = defaultdict(lambda: defaultdict(int))
        self.unigram_counts = defaultdict(int)
        self.is_fitted = False

    def fit(self, benign_traces: List[List[str]]):
        """Build transition frequency matrix from benign tool category sequences."""
        for trace in benign_traces:
            for i in range(len(trace)):
                curr = trace[i]
                self.unigram_counts[curr] += 1
                if i > 0:
                    prev = trace[i - 1]
                    self.bigram_counts[prev][curr] += 1
        self.is_fitted = True

    def transition_probability(self, prev_tool: str, curr_tool: str) -> float:
        if not self.is_fitted or self.unigram_counts[prev_tool] == 0:
            return 0.50 # Default prior
        count = self.bigram_counts[prev_tool][curr_tool]
        total = self.unigram_counts[prev_tool]
        return float(count) / float(total)

    def predict(self, prev_tool: str, curr_tool: str) -> bool:
        """Returns True if transition probability is below rarity threshold."""
        prob = self.transition_probability(prev_tool, curr_tool)
        return prob < self.threshold
