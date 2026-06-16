# app/services/recommendation_engine.py
"""
AI Shield Security Recommendations Engine
Generates risk-based suggestions and remediation advice based on scan results.
"""

class RecommendationEngine:
    @staticmethod
    def get_recommendations(prediction: str, risk_score: int, confidence: float) -> dict:
        """
        Retrieves threat level, risk details, and actionable mitigation advice.
        """
        confidence_pct = int(confidence * 100) if confidence <= 1.0 else int(confidence)
        
        if prediction == "Phishing" or risk_score >= 70:
            return {
                "threat_level": "CRITICAL",
                "color_code": "danger",
                "risk_score": risk_score,
                "confidence_score": confidence_pct,
                "threat_category": "Confirmed Phishing Signature",
                "summary": "This resource matches known phishing patterns or is flagged by threat intelligence feeds. Immediate containment required.",
                "recommendations": [
                    "Do not visit this website or click any links within it.",
                    "Do not enter credentials, financial tokens, or personal data.",
                    "Block the domain immediately on enterprise firewalls and DNS security routers.",
                    "Report this incident to your corporate security operations center.",
                    "Add the domain indicators to your local threat intelligence database/blacklist."
                ]
            }
        elif prediction == "Suspicious" or risk_score >= 35:
            return {
                "threat_level": "WARNING",
                "color_code": "warning",
                "risk_score": risk_score,
                "confidence_score": confidence_pct,
                "threat_category": "Potential Threat / Anomaly",
                "summary": "This URL exhibits characteristics often associated with credential harvesting or domain hijacking, but lacks clear blacklist matches.",
                "recommendations": [
                    "Avoid entering credentials or authentication tokens on this site.",
                    "Verify the domain registration date and ownership manually.",
                    "Check SSL certificate validation status and certificate issuer info.",
                    "Inspect redirect pathways for double redirections or suspicious ports.",
                    "Flag the URL in security monitoring archives for follow-up observation."
                ]
            }
        else:
            return {
                "threat_level": "LOW",
                "color_code": "success",
                "risk_score": risk_score,
                "confidence_score": confidence_pct,
                "threat_category": "Legitimate / Safe Resource",
                "summary": "No threat signatures detected. The URL matches trusted pattern libraries and exhibits solid domain trust indices.",
                "recommendations": [
                    "Website appears legitimate based on current threat intel state.",
                    "Verify domain ownership if input requests seem unusual.",
                    "Continue monitoring for potential content changes or hijackings."
                ]
            }
