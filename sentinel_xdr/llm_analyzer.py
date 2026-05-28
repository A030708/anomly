# sentinel_xdr/llm_analyzer.py

import os
import logging
from groq import Groq
from datetime import datetime

logger = logging.getLogger(__name__)


class LLMAnalyzer:
    def __init__(self):
        self.client = Groq(api_key=os.getenv("GROQ_API_KEY"))
        self.model = "llama-3.1-8b-instant"

    def analyze(self, event: dict, context: dict,
                attack_type: str, score: float, severity: str) -> dict:
        """Send event to Groq for analysis. Returns analysis dict."""

        prior_events = context.get("recent_events_10", [])
        ip_history = context.get("ip_history", {})

        prior_str = "\n".join([
            f"  - [{e.get('timestamp', '')[:19]}] {e.get('event_type')} "
            f"on {e.get('route')} (score: {e.get('anomaly_score', 0):.2f})"
            for e in prior_events[:10]
        ])

        systems_accessed = []
        if ip_history.get("seen_on_boltmart"):
            systems_accessed.append("BoltMart (Public Shop)")
        if ip_history.get("seen_on_warehouse"):
            systems_accessed.append("WarehouseOS (Internal)")

        prompt = f"""ANOMALOUS EVENT DETECTED — SECURITY ANALYSIS REQUIRED

Source System: {event.get('source', 'unknown').upper()}
Attack Type: {attack_type}
Anomaly Score: {score:.2f} / 1.0
Severity: {severity.upper()}

Current Event:
- IP Address: {event.get('ip', 'unknown')}
- Route: {event.get('route', '/')}
- Method: {event.get('method', 'GET')}
- Event Type: {event.get('event_type', 'unknown')}
- Timestamp: {event.get('timestamp', datetime.now().isoformat())[:19]}
- Metadata: {event.get('metadata', {})}

Last 10 Events from this IP:
{prior_str if prior_str else '  - No prior events found (new IP)'}

IP History:
- First seen: {ip_history.get('first_seen', 'Unknown')}
- Total events: {ip_history.get('total_events', 0)}
- Prior blocks: {ip_history.get('prior_blocks', 0)}
- Systems accessed: {', '.join(systems_accessed) if systems_accessed else 'Single system'}
- Blocked on another system: {'YES - HIGH RISK' if ip_history.get('blocked_on_other') else 'No'}

Based on this data, provide:
1. A plain English explanation of what attack is occurring (2-3 sentences)
2. Why this is dangerous for the business (1-2 sentences)
3. What the attacker is likely trying to achieve (1 sentence)
4. Exactly one recommendation from: BLOCK_IP, RATE_LIMIT, HOLD_FOR_REVIEW, or WATCH_AND_LOG
5. One sentence explaining your recommendation

Format your response exactly as:
ANALYSIS: [your analysis here]
BUSINESS_IMPACT: [impact here]
ATTACKER_GOAL: [goal here]
RECOMMENDATION: [one of the four actions]
REASONING: [one sentence]"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a senior cybersecurity analyst at an enterprise SOC. "
                                  "Be specific, concise, and always recommend concrete action. "
                                  "Never make up data — only analyze what is provided."
                    },
                    {"role": "user", "content": prompt}
                ],
                max_tokens=400,
                temperature=0.3
            )

            content = response.choices[0].message.content
            return self._parse_response(content)

        except Exception as e:
            logger.error(f"Groq API error: {e}")
            return self._fallback_analysis(attack_type, score, severity)

    def _parse_response(self, content: str) -> dict:
        """Parse the structured Groq response."""
        result = {
            "analysis": "",
            "business_impact": "",
            "attacker_goal": "",
            "recommendation": "WATCH_AND_LOG",
            "reasoning": "",
            "full_text": content
        }

        lines = content.strip().split("\n")
        for line in lines:
            if line.startswith("ANALYSIS:"):
                result["analysis"] = line[9:].strip()
            elif line.startswith("BUSINESS_IMPACT:"):
                result["business_impact"] = line[16:].strip()
            elif line.startswith("ATTACKER_GOAL:"):
                result["attacker_goal"] = line[14:].strip()
            elif line.startswith("RECOMMENDATION:"):
                rec = line[15:].strip()
                valid = ["BLOCK_IP", "RATE_LIMIT", "HOLD_FOR_REVIEW", "WATCH_AND_LOG"]
                if rec in valid:
                    result["recommendation"] = rec
            elif line.startswith("REASONING:"):
                result["reasoning"] = line[10:].strip()

        # Fallback: extract recommendation from anywhere in text
        if result["recommendation"] == "WATCH_AND_LOG":
            for action in ["BLOCK_IP", "RATE_LIMIT", "HOLD_FOR_REVIEW"]:
                if action in content:
                    result["recommendation"] = action
                    break

        return result

    def _fallback_analysis(self, attack_type: str, score: float, severity: str) -> dict:
        """Fallback when Groq is unavailable."""
        return {
            "analysis": f"Automated detection identified {attack_type} with score {score:.2f}.",
            "business_impact": "Potential unauthorized access or data compromise detected.",
            "attacker_goal": "Attempting to exploit system vulnerabilities.",
            "recommendation": "BLOCK_IP" if score >= 0.85 else "WATCH_AND_LOG",
            "reasoning": "Score exceeds critical threshold requiring immediate response.",
            "full_text": f"Fallback analysis for {attack_type}"
        }

    def generate_daily_summary(self, incidents: list) -> str:
        """Generate executive summary for daily report."""
        if not incidents:
            return "No security incidents were recorded in the past 24 hours. All systems operating normally."

        incident_text = "\n".join([
            f"- {i.get('incident_id')}: {i.get('attack_type')} "
            f"({i.get('severity')}) from {i.get('ip_address')}"
            for i in incidents[:20]
        ])

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a CISO writing a morning security briefing. "
                                  "Be executive-level: clear, concise, actionable."
                    },
                    {
                        "role": "user",
                        "content": f"Write a 2-paragraph executive security summary for "
                                  f"the past 24 hours based on these incidents:\n\n{incident_text}\n\n"
                                  f"Include: top threat types, most targeted assets, "
                                  f"response effectiveness, recommended posture adjustments."
                    }
                ],
                max_tokens=300,
                temperature=0.4
            )
            return response.choices[0].message.content
        except:
            count = len(incidents)
            critical = sum(1 for i in incidents if i.get("severity") == "critical")
            return (f"Security Operations Summary: {count} incidents detected in the past 24 hours, "
                   f"including {critical} critical severity events. All incidents were automatically "
                   f"triaged by Sentinel XDR. Recommend reviewing critical incidents before market open.")
