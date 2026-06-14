import os
import sys

# Add project root to path to resolve imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import joblib
import numpy as np
from app.config import Config
from ml.feature_extraction.feature_extractor import extract_features, get_vector, get_feature_names
import pandas as pd

class PhishingPredictor:
    def __init__(self, model_path=None):
        self.model_path = model_path or Config.MODEL_PATH
        self.model_data = None
        self.model = None
        self.load_model()

    def load_model(self):
        """Loads the trained ML model from file."""
        if os.path.exists(self.model_path):
            try:
                self.model_data = joblib.load(self.model_path)
                self.model = self.model_data['model']
                print(f"[+] Loaded ML model from {self.model_path}")
            except Exception as e:
                print(f"[-] Error loading model from {self.model_path}: {e}")
                self.model = None
        else:
            print(f"[-] Model file not found at {self.model_path}. Please run train.py first.")
            self.model = None

    def predict(self, url: str, online: bool = False) -> dict:
        """
        Predicts if a URL is Legitimate, Suspicious, or Phishing.
        
        Returns a dict containing:
          - prediction: 'Legitimate', 'Suspicious', or 'Phishing'
          - confidence: float (0.0 to 1.0)
          - risk_score: int (0 to 100)
          - features: dict (extracted features)
        """
        # 1. Extract Features
        features = extract_features(url, online=online)
        vector = get_vector(features)
        
        # 2. Check if model is loaded, if not, do a rule-based fallback
        if self.model is None:
            # Fallback rule-based prediction
            phish_points = 0
            if features['has_ip']: phish_points += 40
            if features['has_at']: phish_points += 20
            if features['is_shortener']: phish_points += 30
            if features['suspicious_keywords'] > 0: phish_points += 25 * features['suspicious_keywords']
            if not features['has_https']: phish_points += 20
            if features['url_length'] > 75: phish_points += 15
            
            risk_score = min(100, phish_points)
            confidence = 0.5  # low confidence since it's a fallback
            
            if risk_score > 60:
                prediction = "Phishing"
            elif risk_score > 30:
                prediction = "Suspicious"
            else:
                prediction = "Legitimate"
                
            return {
                "prediction": prediction,
                "confidence": confidence,
                "risk_score": risk_score,
                "features": features,
                "model_used": "Fallback Rule Engine"
            }

        # 3. Model Inference
        # Wrap in pandas DataFrame to preserve feature names and avoid scikit-learn UserWarning
        sample = pd.DataFrame([vector], columns=get_feature_names())
        prob = self.model.predict_proba(sample)[0]  # [prob_legit, prob_phish]
        phishing_prob = prob[1]
        
        # Calculate AI Risk Score (0 - 100)
        # Combined weight: 60% model probability + 40% critical heuristic features
        heuristic_score = 0
        if features['has_ip']: heuristic_score += 30
        if features['is_shortener']: heuristic_score += 20
        if features['suspicious_keywords'] > 0: heuristic_score += 25
        if not features['has_https']: heuristic_score += 25
        heuristic_score = min(100, heuristic_score)
        
        risk_score = int((phishing_prob * 60) + (heuristic_score * 0.4))
        
        # Map to classes
        # Phishing: Risk >= 70 or model phishing prob >= 0.70
        # Suspicious: Risk between 35 and 69, or model phishing prob between 0.35 and 0.69
        # Legitimate: Risk < 35 and model phishing prob < 0.35
        if phishing_prob >= 0.70 or risk_score >= 70:
            prediction = "Phishing"
            confidence = float(phishing_prob if phishing_prob >= 0.5 else 1 - phishing_prob)
        elif phishing_prob >= 0.35 or risk_score >= 35:
            prediction = "Suspicious"
            confidence = float(max(phishing_prob, 1 - phishing_prob))
        else:
            prediction = "Legitimate"
            confidence = float(prob[0])  # probability of being legitimate

        return {
            "prediction": prediction,
            "confidence": round(confidence, 4),
            "risk_score": risk_score,
            "features": features,
            "model_used": self.model_data.get('model_name', 'Random Forest Classifier') if self.model_data else "Fallback Rule Engine"
        }
