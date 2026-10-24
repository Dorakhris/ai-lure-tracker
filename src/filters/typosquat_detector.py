"""
AI Lure Tracker - Typosquat & Lookalike Detector
Calculates Levenshtein and Damerau-Levenshtein distance against targeted brands and AI libraries.
"""

from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger("ai_lure_tracker.filters.typosquat")


def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Computes standard Levenshtein edit distance between two strings.
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def damerau_levenshtein_distance(s1: str, s2: str) -> int:
    """
    Computes Damerau-Levenshtein distance (includes adjacent character transpositions).
    Essential for detecting typos like 'oepnai' -> 'openai' or 'anthroipc' -> 'anthropic'.
    """
    d: Dict[Tuple[int, int], int] = {}
    len1 = len(s1)
    len2 = len(s2)

    for i in range(-1, len1 + 1):
        d[(i, -1)] = i + 1
    for j in range(-1, len2 + 1):
        d[(-1, j)] = j + 1

    for i in range(len1):
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            d[(i, j)] = min(
                d[(i - 1, j)] + 1,        # deletion
                d[(i, j - 1)] + 1,        # insertion
                d[(i - 1, j - 1)] + cost  # substitution
            )
            if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + 1)  # transposition

    return d[(len1 - 1, len2 - 1)]


class TyposquatDetector:
    def __init__(self, target_libraries: List[str], max_distance: int = 2):
        self.target_libraries = [lib.lower().strip() for lib in target_libraries]
        self.max_distance = max_distance

    def check_package_typosquat(self, candidate_name: str) -> Optional[Tuple[str, int]]:
        """
        Checks if candidate_name is a lookalike/typosquat of any targeted AI library.
        Returns (target_library, distance) if within max_distance and not identical.
        """
        cand = candidate_name.lower().strip().replace("_", "-")
        for target in self.target_libraries:
            tgt = target.lower().strip().replace("_", "-")
            if cand == tgt:
                # Exact match is the legitimate package itself (handled by whitelist)
                continue

            dist = damerau_levenshtein_distance(cand, tgt)
            if dist <= self.max_distance:
                return (target, dist)

            # Check common typosquatting patterns:
            # e.g., 'python-openai', 'openai-official', 'langchain-v2', 'openai-client'
            if cand.startswith(f"{tgt}-") or cand.endswith(f"-{tgt}"):
                return (target, 1)

        return None
