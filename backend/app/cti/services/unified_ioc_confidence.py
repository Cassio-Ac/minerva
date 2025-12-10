"""
Unified IOC Confidence Scorer

Calculates confidence scores for IOCs based on:
- Base score from source reputation
- Multi-source correlation boost
- Time decay (older IOCs less confident)
- Source reputation weighting
"""

import math
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional


class IOCConfidenceScorer:
    """Calculates unified confidence scores for IOCs"""

    # Base scores by source (0-100)
    BASE_SCORES = {
        # High quality curated sources
        "virustotal": 85,
        "threatfox": 75,
        "unit42": 85,
        "emerging_threats": 70,
        "urlhaus": 70,

        # Government/CERT sources
        "circl": 65,

        # Community-driven sources
        "misp": 60,
        "otx": 50,

        # Reputation sources (future)
        "abuseipdb": 70,
        "shodan": 65,

        # Other/Custom
        "custom": 50,
        "unknown": 40,
    }

    # Source reputation scores (0.0 - 1.0)
    SOURCE_REPUTATION = {
        "virustotal": 0.95,
        "unit42": 0.95,
        "threatfox": 0.90,
        "emerging_threats": 0.85,
        "urlhaus": 0.85,
        "circl": 0.80,
        "abuseipdb": 0.80,
        "misp": 0.75,
        "shodan": 0.75,
        "otx": 0.70,
        "custom": 0.50,
        "unknown": 0.40,
    }

    # Time decay settings
    HALF_LIFE_DAYS = 90  # Confidence halves every 90 days
    MIN_DECAY = 0.30     # Never decay below 30%

    def calculate(
        self,
        sources: List[Dict[str, Any]],
        last_seen: Optional[datetime] = None,
        ioc_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Calculate unified confidence score with full breakdown.

        Args:
            sources: List of source objects with source_name and source_confidence
            last_seen: When the IOC was last observed
            ioc_type: Type of IOC (for potential type-specific adjustments)

        Returns:
            Dictionary with confidence_score, confidence_level, and confidence_breakdown
        """
        if not sources:
            return self._empty_confidence()

        # 1. Calculate base score (use highest among sources)
        base_score = self._calculate_base_score(sources)

        # 2. Multi-source boost
        multi_source_boost = self._calculate_multi_source_boost(len(sources))

        # 3. Reputation factor
        reputation_factor = self._calculate_reputation_factor(sources)

        # 4. Time decay
        time_decay = self._calculate_time_decay(last_seen)

        # 5. Calculate final score
        final_score = base_score * multi_source_boost * reputation_factor * time_decay
        final_score = min(100.0, max(0.0, final_score))  # Clamp to 0-100

        # 6. Determine confidence level
        confidence_level = self._get_confidence_level(final_score)

        return {
            "confidence_score": round(final_score, 2),
            "confidence_level": confidence_level,
            "confidence_breakdown": {
                "base_score": round(base_score, 2),
                "multi_source_boost": round(multi_source_boost, 3),
                "reputation_boost": round(reputation_factor, 3),
                "time_decay": round(time_decay, 3),
                "final_score": round(final_score, 2)
            }
        }

    def _calculate_base_score(self, sources: List[Dict[str, Any]]) -> float:
        """
        Calculate base score from sources.
        Uses the highest base score among all sources, weighted by source confidence.
        """
        if not sources:
            return 40.0

        scores = []
        for source in sources:
            source_name = source.get("source_name", "unknown").lower()
            base = self.BASE_SCORES.get(source_name, self.BASE_SCORES["unknown"])

            # Weight by source's own confidence if provided
            source_conf = source.get("source_confidence", 1.0)
            if isinstance(source_conf, str):
                source_conf = {"low": 0.3, "medium": 0.6, "high": 0.9}.get(source_conf.lower(), 0.6)

            weighted_score = base * source_conf
            scores.append(weighted_score)

        # Use maximum score (most confident source determines base)
        return max(scores) if scores else 40.0

    def _calculate_multi_source_boost(self, source_count: int) -> float:
        """
        Calculate boost when same IOC appears in multiple sources.
        Diminishing returns after 3 sources.

        Returns multiplier (1.0 = no boost, 1.7 = max 70% boost)
        """
        if source_count <= 1:
            return 1.0
        elif source_count == 2:
            return 1.25  # +25%
        elif source_count == 3:
            return 1.45  # +45%
        elif source_count == 4:
            return 1.55  # +55%
        elif source_count == 5:
            return 1.60  # +60%
        else:
            # Cap at 70% boost
            return min(1.70, 1.60 + (source_count - 5) * 0.02)

    def _calculate_reputation_factor(self, sources: List[Dict[str, Any]]) -> float:
        """
        Calculate reputation factor based on source quality.
        Weights sources by their reputation scores.

        Returns multiplier (0.8 to 1.2 range)
        """
        if not sources:
            return 1.0

        total_rep = 0.0
        for source in sources:
            source_name = source.get("source_name", "unknown").lower()
            rep = self.SOURCE_REPUTATION.get(source_name, self.SOURCE_REPUTATION["unknown"])
            total_rep += rep

        avg_rep = total_rep / len(sources)

        # Scale to 0.8-1.2 range
        # avg_rep 0.0 -> factor 0.8
        # avg_rep 0.5 -> factor 1.0
        # avg_rep 1.0 -> factor 1.2
        return 0.8 + (avg_rep * 0.4)

    def _calculate_time_decay(self, last_seen: Optional[datetime]) -> float:
        """
        Calculate time decay factor using exponential decay.
        Older IOCs get lower confidence as they may no longer be active.

        Formula: decay = 0.5 ^ (days_since_last_seen / half_life_days)

        Returns multiplier (MIN_DECAY to 1.0)
        """
        if last_seen is None:
            return 1.0

        # Ensure timezone-aware comparison
        now = datetime.now(timezone.utc)

        if isinstance(last_seen, str):
            try:
                last_seen = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
            except ValueError:
                return 1.0

        # Make last_seen timezone-aware if it isn't
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)

        days_since = (now - last_seen).days

        if days_since <= 0:
            return 1.0

        # Exponential decay
        decay = math.pow(0.5, days_since / self.HALF_LIFE_DAYS)

        # Apply minimum floor
        return max(self.MIN_DECAY, decay)

    def _get_confidence_level(self, score: float) -> str:
        """Convert numeric score to categorical level"""
        if score >= 85:
            return "critical"
        elif score >= 70:
            return "high"
        elif score >= 50:
            return "medium"
        elif score >= 30:
            return "low"
        else:
            return "informational"

    def _empty_confidence(self) -> Dict[str, Any]:
        """Return empty confidence structure"""
        return {
            "confidence_score": 0.0,
            "confidence_level": "informational",
            "confidence_breakdown": {
                "base_score": 0.0,
                "multi_source_boost": 1.0,
                "reputation_boost": 1.0,
                "time_decay": 1.0,
                "final_score": 0.0
            }
        }

    def recalculate_with_new_source(
        self,
        current_confidence: Dict[str, Any],
        current_sources: List[Dict[str, Any]],
        new_source: Dict[str, Any],
        last_seen: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Recalculate confidence after adding a new source.
        Convenience method for correlation engine.
        """
        # Add new source to list
        updated_sources = current_sources + [new_source]

        # Recalculate
        return self.calculate(updated_sources, last_seen)

    def estimate_confidence_impact(
        self,
        current_score: float,
        current_source_count: int,
        new_source_name: str
    ) -> Dict[str, Any]:
        """
        Estimate the impact of adding a new source.
        Useful for previewing correlation benefits.
        """
        # Current multi-source boost
        current_boost = self._calculate_multi_source_boost(current_source_count)

        # New multi-source boost
        new_boost = self._calculate_multi_source_boost(current_source_count + 1)

        # Boost increase
        boost_increase = new_boost - current_boost

        # New source reputation
        new_rep = self.SOURCE_REPUTATION.get(new_source_name.lower(), 0.5)

        # Estimated new score (simplified)
        estimated_score = current_score * (new_boost / current_boost)
        estimated_score = min(100.0, estimated_score)

        return {
            "current_score": current_score,
            "estimated_new_score": round(estimated_score, 2),
            "score_increase": round(estimated_score - current_score, 2),
            "new_source_reputation": new_rep,
            "boost_increase_percent": round(boost_increase * 100, 1)
        }


# Singleton instance
_scorer = None

def get_confidence_scorer() -> IOCConfidenceScorer:
    """Get singleton scorer instance"""
    global _scorer
    if _scorer is None:
        _scorer = IOCConfidenceScorer()
    return _scorer
