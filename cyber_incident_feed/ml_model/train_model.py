"""
Machine Learning model training for Indian cybersecurity incident classification
"""
import os
import pickle
import logging
import pandas as pd
import numpy as np
from datetime import datetime
from typing import List, Tuple, Dict, Any, Optional
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix
)
from sklearn.pipeline import Pipeline
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk.stem import WordNetLemmatizer

from config import ML_CONFIG, INCIDENT_CATEGORIES, KNOWN_APT_GROUPS
from database.db_setup import db_manager

# Download required NLTK data
try:
    nltk.download('punkt', quiet=True)
    nltk.download('stopwords', quiet=True)
    nltk.download('wordnet', quiet=True)
    nltk.download('omw-1.4', quiet=True)
except:
    pass

logger = logging.getLogger(__name__)

class IndianCyberIncidentClassifier:
    """
    ML classifier for identifying Indian cybersecurity incidents
    """
    
    def __init__(self):
        """Initialize the classifier"""
        self.model = None
        self.vectorizer = None
        self.pipeline = None
        self.feature_names = []
        self.training_date = None
        
        # Initialize NLTK components
        try:
            self.stop_words = set(stopwords.words('english'))
            self.lemmatizer = WordNetLemmatizer()
        except:
            logger.warning("NLTK data not available, using basic preprocessing")
            self.stop_words = set()
            self.lemmatizer = None
    
    def _preprocess_text(self, text: str) -> str:
        """
        Preprocess text for ML model
        
        Args:
            text: Raw text to preprocess
            
        Returns:
            Preprocessed text
        """
        if not text:
            return ""
        
        text = text.lower()
        
        # Remove special characters but keep some important ones
        import re
        text = re.sub(r'[^a-zA-Z0-9\s\-_.]', ' ', text)
        
        # Tokenize if NLTK is available
        if self.lemmatizer:
            try:
                tokens = word_tokenize(text)
                # Remove stopwords and lemmatize
                tokens = [
                    self.lemmatizer.lemmatize(token) 
                    for token in tokens 
                    if token not in self.stop_words and len(token) > 2
                ]
                return ' '.join(tokens)
            except:
                pass
        
        # Fallback: basic preprocessing
        words = text.split()
        words = [word for word in words if len(word) > 2]
        return ' '.join(words)
    
    def _create_training_data(self) -> Tuple[List[str], List[int], List[str]]:
        """
        Create training data from various sources
        
        Returns:
            Tuple of (texts, labels, categories)
        """
        texts = []
        labels = []  # 1 for Indian cyber incident, 0 for irrelevant
        categories = []
        
        # Positive examples (Indian cyber incidents)
        indian_cyber_examples = [
            "Indian government websites hit by major cyber attack from Pakistan-based hackers",
            "AIIMS Delhi servers compromised in ransomware attack, patient data at risk",
            "Paytm reports data breach affecting millions of Indian users' financial information",
            "Indian IT companies Infosys and TCS face sophisticated APT attacks",
            "CERT-In warns of phishing campaigns targeting Indian banking customers",
            "Delhi Police cybercrime unit arrests hackers in UPI fraud case",
            "Indian Railways booking system suffers DDoS attack during festival season",
            "Aadhaar database vulnerabilities exposed by security researchers",
            "Indian startup unicorns face increased cybersecurity threats",
            "State Bank of India mobile app vulnerability allows account takeover",
            "Indian defense research organizations targeted by Chinese APT groups",
            "Bangalore-based tech firm loses customer data in supply chain attack",
            "Indian pharmaceutical companies hit by ransomware during COVID-19",
            "Mumbai airport systems disrupted by cyber attack on critical infrastructure",
            "Indian e-commerce platforms face massive credential stuffing attacks",
            "Hyderabad IT corridor companies report spear-phishing campaigns",
            "Indian government launches cybersecurity framework after AIIMS breach",
            "Chennai-based software company discovers insider threat in HR systems",
            "Indian fintech sector sees 300% increase in cyber attacks this year",
            "New Delhi cybersecurity summit addresses growing digital threats",
            "Indian space research organization ISRO reports attempted data theft",
            "Pune IT park faces coordinated cyber attacks on multiple companies",
            "Indian oil companies targeted by sophisticated malware campaigns",
            "Kolkata bank branches hit by ATM skimming malware operations",
            "Indian telecom operators report SS7 protocol exploitation attempts"
        ]
        
        # Negative examples (non-Indian or non-cyber)
        negative_examples = [
            "US elections face disinformation campaigns on social media platforms",
            "European banks implement new GDPR compliance measures for data protection",
            "Chinese manufacturing sector adopts new industrial IoT security standards",
            "Australian government updates national cybersecurity strategy framework",
            "Canadian healthcare systems upgrade legacy infrastructure for better security",
            "Japanese companies invest heavily in quantum-resistant encryption technologies",
            "German automotive industry faces supply chain vulnerabilities",
            "UK financial services sector reports decline in fraud incidents",
            "Brazilian telecommunications infrastructure receives major security upgrades",
            "South Korean gaming companies implement enhanced user authentication",
            "Apple releases new iOS security features for enterprise users",
            "Microsoft announces expanded threat intelligence services globally",
            "Google launches new privacy controls for international markets",
            "Facebook implements stricter content moderation policies worldwide",
            "Amazon Web Services expands cybersecurity offerings in Europe",
            "Netflix increases investment in content protection technologies",
            "Tesla improves vehicle cybersecurity measures across all models",
            "Zoom enhances end-to-end encryption for business customers",
            "Twitter updates API security protocols for developer access",
            "LinkedIn strengthens professional network security measures",
            "Weather forecast shows heavy rainfall expected next week",
            "Stock market shows positive trends in technology sector",
            "New restaurant opens in downtown featuring fusion cuisine",
            "Sports team wins championship after exceptional playoff performance",
            "Celebrity couple announces engagement at award ceremony event"
        ]
        
        # Add positive examples
        for example in indian_cyber_examples:
            texts.append(example)
            labels.append(1)
            categories.append('Indian Cyber Incident')
        
        # Add negative examples
        for example in negative_examples:
            texts.append(example)
            labels.append(0)
            categories.append('Irrelevant')
        
        # Get data from database if available
        try:
            with db_manager.get_session() as session:
                from ..database.models import Incident
                
                # Get labeled incidents from database
                incidents = session.query(Incident).filter(
                    Incident.india_related.isnot(None)
                ).limit(1000).all()
                
                for incident in incidents:
                    text = f"{incident.title} {incident.description or ''}"
                    texts.append(text)
                    labels.append(1 if incident.india_related else 0)
                    categories.append(incident.category or 'Unknown')
        
        except Exception as e:
            logger.warning(f"Could not load data from database: {e}")
        
        logger.info(f"Created training dataset with {len(texts)} examples")
        logger.info(f"Positive examples: {sum(labels)}, Negative examples: {len(labels) - sum(labels)}")
        
        return texts, labels, categories
    
    def train_model(self, test_size: float = 0.2, random_state: int = 42) -> Dict[str, float]:
        """
        Train the classification model
        
        Args:
            test_size: Proportion of data to use for testing
            random_state: Random seed for reproducibility
            
        Returns:
            Dictionary with training metrics
        """
        logger.info("Starting model training...")
        
        # Create training data
        texts, labels, categories = self._create_training_data()
        
        if len(texts) < 10:
            raise ValueError("Insufficient training data. Need at least 10 examples.")
        
        # Preprocess texts
        processed_texts = [self._preprocess_text(text) for text in texts]
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            processed_texts, labels, test_size=test_size, 
            random_state=random_state, stratify=labels
        )
        
        # Create pipeline with TF-IDF vectorizer and classifier
        self.pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(
                max_features=5000,
                min_df=2,
                max_df=0.95,
                ngram_range=(1, 2),
                stop_words='english'
            )),
            ('classifier', LogisticRegression(
                random_state=random_state,
                max_iter=1000,
                class_weight='balanced'
            ))
        ])
        
        # Perform hyperparameter tuning
        param_grid = {
            'tfidf__max_features': [3000, 5000, 8000],
            'tfidf__ngram_range': [(1, 1), (1, 2)],
            'classifier__C': [0.1, 1.0, 10.0]
        }
        
        grid_search = GridSearchCV(
            self.pipeline, param_grid, cv=3, 
            scoring='f1', n_jobs=-1, verbose=1
        )
        
        grid_search.fit(X_train, y_train)
        
        # Use best model
        self.pipeline = grid_search.best_estimator_
        logger.info(f"Best parameters: {grid_search.best_params_}")
        
        # Make predictions
        y_pred = self.pipeline.predict(X_test)
        y_pred_proba = self.pipeline.predict_proba(X_test)[:, 1]
        
        # Calculate metrics
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred),
            'recall': recall_score(y_test, y_pred),
            'f1_score': f1_score(y_test, y_pred)
        }
        
        # Cross-validation
        cv_scores = cross_val_score(self.pipeline, processed_texts, labels, cv=5, scoring='f1')
        metrics['cv_mean'] = cv_scores.mean()
        metrics['cv_std'] = cv_scores.std()
        
        self.training_date = datetime.now()
        
        logger.info("Training completed successfully!")
        logger.info(f"Accuracy: {metrics['accuracy']:.3f}")
        logger.info(f"Precision: {metrics['precision']:.3f}")
        logger.info(f"Recall: {metrics['recall']:.3f}")
        logger.info(f"F1-Score: {metrics['f1_score']:.3f}")
        logger.info(f"CV F1-Score: {metrics['cv_mean']:.3f} (+/- {metrics['cv_std']*2:.3f})")
        
        # Print detailed classification report
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=['Irrelevant', 'Indian Cyber']))
        
        return metrics
    
    def save_model(self, model_path: str = None, vectorizer_path: str = None):
        """
        Save trained model to disk
        
        Args:
            model_path: Path to save model
            vectorizer_path: Path to save vectorizer (deprecated, using pipeline)
        """
        if self.pipeline is None:
            raise ValueError("No trained model to save. Train model first.")
        
        if model_path is None:
            model_path = ML_CONFIG['model_path']
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        
        # Save the entire pipeline
        with open(model_path, 'wb') as f:
            pickle.dump({
                'pipeline': self.pipeline,
                'training_date': self.training_date,
                'version': '1.0'
            }, f)
        
        logger.info(f"Model saved to {model_path}")
    
    def load_model(self, model_path: str = None):
        """
        Load trained model from disk
        
        Args:
            model_path: Path to load model from
        """
        if model_path is None:
            model_path = ML_CONFIG['model_path']
        
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found: {model_path}")
        
        with open(model_path, 'rb') as f:
            model_data = pickle.load(f)
        
        self.pipeline = model_data['pipeline']
        self.training_date = model_data.get('training_date')
        
        logger.info(f"Model loaded from {model_path}")
    
    def predict(self, text: str) -> Tuple[bool, float]:
        """
        Predict if text is about Indian cybersecurity incident
        
        Args:
            text: Text to classify
            
        Returns:
            Tuple of (is_relevant, confidence_score)
        """
        if self.pipeline is None:
            raise ValueError("No trained model available. Train or load model first.")
        
        processed_text = self._preprocess_text(text)
        
        # Get prediction and probability
        prediction = self.pipeline.predict([processed_text])[0]
        probability = self.pipeline.predict_proba([processed_text])[0]
        
        is_relevant = bool(prediction)
        confidence_score = float(probability[1])  # Probability of being relevant
        
        return is_relevant, confidence_score
    
    def predict_category(self, text: str) -> str:
        """
        Predict incident category (simplified implementation)
        
        Args:
            text: Text to classify
            
        Returns:
            Predicted category
        """
        text_lower = text.lower()
        
        # Simple keyword-based category prediction
        if any(word in text_lower for word in ['ransomware', 'encrypt', 'decrypt', 'ransom']):
            return 'Ransomware'
        elif any(word in text_lower for word in ['phishing', 'phish', 'fake email', 'suspicious email']):
            return 'Phishing'
        elif any(word in text_lower for word in ['ddos', 'denial of service', 'overwhelm']):
            return 'DDoS Attack'
        elif any(word in text_lower for word in ['malware', 'virus', 'trojan', 'worm']):
            return 'Malware'
        elif any(word in text_lower for word in ['breach', 'leak', 'exposed', 'stolen data']):
            return 'Data Breach'
        elif any(word in text_lower for word in ['vulnerability', 'exploit', 'zero-day', 'cve']):
            return 'Vulnerability Disclosure'
        else:
            return 'Other'
    
    def get_feature_importance(self, top_n: int = 20) -> List[Tuple[str, float]]:
        """
        Get top features that contribute to classification
        
        Args:
            top_n: Number of top features to return
            
        Returns:
            List of (feature_name, importance_score) tuples
        """
        if self.pipeline is None:
            return []
        
        # Get feature names from TF-IDF vectorizer
        vectorizer = self.pipeline.named_steps['tfidf']
        classifier = self.pipeline.named_steps['classifier']
        
        feature_names = vectorizer.get_feature_names_out()
        coefficients = classifier.coef_[0]
        
        # Get top positive and negative features
        feature_importance = list(zip(feature_names, coefficients))
        feature_importance.sort(key=lambda x: abs(x[1]), reverse=True)
        
        return feature_importance[:top_n]

def main():
    """Main function for training the model"""
    classifier = IndianCyberIncidentClassifier()
    
    try:
        # Train model
        metrics = classifier.train_model()
        
        # Save model
        classifier.save_model()
        
        # Test with sample texts
        test_texts = [
            "Indian government websites hit by cyber attack",
            "US election security measures updated",
            "AIIMS Delhi ransomware attack affects patient data"
        ]
        
        print("\nSample Predictions:")
        for text in test_texts:
            is_relevant, confidence = classifier.predict(text)
            category = classifier.predict_category(text)
            print(f"Text: {text}")
            print(f"Relevant: {is_relevant}, Confidence: {confidence:.3f}, Category: {category}")
            print("-" * 50)
        
        # Show important features
        print("\nTop Important Features:")
        for feature, importance in classifier.get_feature_importance(10):
            print(f"{feature}: {importance:.3f}")
        
    except Exception as e:
        logger.error(f"Training failed: {e}")
        raise

if __name__ == "__main__":
    main()

