from collections import defaultdict, deque
from typing import Dict, List, Any, Optional, Tuple
import threading
import numpy as np

class ContextManager:
    """
    Manages conversation context per session and detects suspicious topic shifts using ML similarity.
    """
    def __init__(self, history_size: int = 20, drift_threshold: float = 0.6, classifier=None):
        self.session_histories: Dict[str, deque] = defaultdict(lambda: deque(maxlen=history_size))
        self.drift_threshold = drift_threshold
        self.lock = threading.Lock()
        self.classifier = classifier  # Should have .embed(text)

    def add_turn(self, session_id: str, prompt: str, response: str, metadata: Optional[dict] = None):
        with self.lock:
            self.session_histories[session_id].append({
                'prompt': prompt,
                'response': response,
                'metadata': metadata or {}
            })

    def detect_topic_drift(self, session_id: str, new_prompt: str) -> Tuple[bool, float]:
        """
        Compare embedding similarity of new prompt to previous N prompts; flags drift if below threshold.
        Returns (bool_drift_detected, similarity_score)
        """
        if not self.classifier or not hasattr(self.classifier, 'embed'):
            return (False, 1.0)  # Classifier missing, cannot check
        with self.lock:
            history = self.session_histories.get(session_id)
            if not history or len(history) == 0:
                return (False, 1.0)
            # Use last 3 prompts for rolling comparison
            prev_prompts = [turn['prompt'] for turn in list(history)[-3:]]
        # Embed new and old
        try:
            new_emb = self.classifier.embed(new_prompt)
            prev_embs = [self.classifier.embed(p) for p in prev_prompts]
            sims = [self._cosine_similarity(new_emb, emb) for emb in prev_embs]
            avg_sim = float(np.mean(sims)) if sims else 1.0
            is_drift = avg_sim < self.drift_threshold
            return (is_drift, avg_sim)
        except Exception:
            return (False, 1.0)

    def get_context_summary(self, session_id: str) -> dict:
        with self.lock:
            hist = self.session_histories.get(session_id, [])
            return {
                'turns': len(hist),
                'last_prompt': hist[-1]['prompt'] if hist else None,
                'last_response': hist[-1]['response'] if hist else None,
            }

    @staticmethod
    def _cosine_similarity(a, b):
        a = np.array(a)
        b = np.array(b)
        return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-9))
