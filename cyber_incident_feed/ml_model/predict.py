"""
Prediction module for real-time incident classification
"""
import logging
import os
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime
import pickle

from ml_model.train_model import IndianCyberIncidentClassifier
from config import ML_CONFIG, INCIDENT_CATEGORIES, SEVERITY_LEVELS, AFFECTED_SECTORS
from database.db_setup import db_manager
from data_scraper.utils import TextProcessor, extract_threat_indicators

logger = logging.getLogger(__name__)

class IncidentPredictor:
    """
    Real-time incident classification and enrichment
    """
    
    def __init__(self):
        """Initialize the predictor"""
        self.classifier = IndianCyberIncidentClassifier()
        self.model_loaded = False
        self._load_model()
    
    def _load_model(self):
        """Load the trained model if available"""
        try:
            if os.path.exists(ML_CONFIG['model_path']):
                self.classifier.load_model()
                self.model_loaded = True
                logger.info("Classification model loaded successfully")
            else:
                logger.warning(f"Model file not found at {ML_CONFIG['model_path']}")
                logger.info("Will train new model when needed")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            self.model_loaded = False
    
    def _ensure_model_loaded(self):
        """Ensure model is loaded or train a new one"""
        if not self.model_loaded:
            logger.info("Training new classification model...")
            try:
                self.classifier.train_model()
                self.classifier.save_model()
                self.model_loaded = True
                logger.info("New model trained and saved successfully")
            except Exception as e:
                logger.error(f"Failed to train new model: {e}")
                raise
    
    def classify_incident(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify a single incident
        
        Args:
            incident_data: Dictionary containing incident information
            
        Returns:
            Enhanced incident data with classification results
        """
        self._ensure_model_loaded()
        
        # Combine title and description for analysis
        text_content = f"{incident_data.get('title', '')} {incident_data.get('description', '')}"
        
        try:
            # Get relevance prediction
            is_relevant, confidence_score = self.classifier.predict(text_content)
            
            # Get category prediction
            category = self.classifier.predict_category(text_content)
            
            # Calculate India relevance score using text processor
            india_score = TextProcessor.calculate_india_relevance_score(text_content)
            
            # Extract Indian entities
            entities = TextProcessor.extract_entities(text_content)
            
            # Extract threat indicators
            threat_indicators = extract_threat_indicators(text_content)
            
            # Determine severity based on content analysis
            severity = self._predict_severity(text_content, threat_indicators)
            
            # Determine affected sector
            sector = self._predict_sector(text_content, entities)
            
            # Update incident data with predictions
            enhanced_data = incident_data.copy()
            enhanced_data.update({
                'relevance_score': confidence_score,
                'is_relevant': is_relevant and confidence_score >= ML_CONFIG['min_confidence'],
                'india_related': is_relevant and india_score > 0.3,
                'category': category,
                'severity': severity,
                'affected_sector': sector,
                'indian_entities': entities,
                'attack_vectors': threat_indicators.get('attack_techniques', []),
                'iocs': threat_indicators.get('iocs', []),
                'apt_group': self._identify_apt_group(text_content, threat_indicators),
                'processed': True
            })
            
            logger.debug(f"Classified incident: {incident_data.get('title', 'Unknown')} - "
                        f"Relevant: {is_relevant}, Confidence: {confidence_score:.3f}")
            
            return enhanced_data
            
        except Exception as e:
            logger.error(f"Classification failed for incident: {e}")
            # Return original data with processing flag
            enhanced_data = incident_data.copy()
            enhanced_data['processed'] = True
            enhanced_data['relevance_score'] = 0.0
            enhanced_data['is_relevant'] = False
            return enhanced_data
    
    def _predict_severity(self, text: str, threat_indicators: Dict) -> str:
        """
        Predict incident severity based on content
        
        Args:
            text: Incident text content
            threat_indicators: Dictionary of threat indicators
            
        Returns:
            Predicted severity level
        """
        text_lower = text.lower()
        
        # Critical severity indicators
        critical_indicators = [
            'critical infrastructure', 'national security', 'government systems',
            'power grid', 'nuclear', 'defense', 'military', 'election systems',
            'banking system collapse', 'nationwide outage'
        ]
        
        # High severity indicators
        high_indicators = [
            'ransomware', 'data breach', 'financial loss', 'customer data',
            'personal information', 'banking', 'healthcare records',
            'supply chain attack', 'zero-day exploit', 'apt attack'
        ]
        
        # Medium severity indicators
        medium_indicators = [
            'phishing', 'malware', 'ddos', 'website defacement',
            'social engineering', 'vulnerability', 'patch available'
        ]
        
        # Check for severity indicators
        if any(indicator in text_lower for indicator in critical_indicators):
            return 'Critical'
        elif any(indicator in text_lower for indicator in high_indicators):
            return 'High'
        elif any(indicator in text_lower for indicator in medium_indicators):
            return 'Medium'
        else:
            return 'Low'
    
    def _predict_sector(self, text: str, entities: Dict) -> str:
        """
        Predict affected sector based on content and entities
        
        Args:
            text: Incident text content
            entities: Dictionary of extracted entities
            
        Returns:
            Predicted affected sector
        """
        text_lower = text.lower()
        
        # Sector indicators
        sector_keywords = {
            'Banking & Finance': [
                'bank', 'financial', 'payment', 'credit card', 'atm',
                'upi', 'paytm', 'phonepe', 'trading', 'stock exchange',
                'insurance', 'loan', 'sbi', 'icici', 'hdfc'
            ],
            'Government': [
                'government', 'ministry', 'department', 'municipal',
                'public sector', 'aadhaar', 'digital india', 'cert-in',
                'administrative', 'bureaucracy', 'policy'
            ],
            'Healthcare': [
                'hospital', 'medical', 'healthcare', 'patient',
                'health records', 'medical device', 'pharma',
                'aiims', 'clinic', 'doctor'
            ],
            'IT & Software': [
                'software', 'technology', 'it company', 'tech firm',
                'infosys', 'tcs', 'wipro', 'hcl', 'tech mahindra',
                'startup', 'unicorn', 'saas'
            ],
            'Education': [
                'university', 'college', 'school', 'education',
                'student', 'academic', 'research', 'iit', 'iim'
            ],
            'Telecommunications': [
                'telecom', 'mobile', 'internet', 'broadband',
                'cellular', 'network', 'airtel', 'jio', 'bsnl'
            ],
            'Energy': [
                'power', 'electricity', 'energy', 'oil', 'gas',
                'renewable', 'solar', 'wind', 'coal', 'petroleum'
            ],
            'Transportation': [
                'railway', 'airport', 'airline', 'transport',
                'metro', 'bus', 'shipping', 'logistics'
            ],
            'Manufacturing': [
                'manufacturing', 'factory', 'industrial', 'production',
                'assembly', 'automotive', 'textile', 'chemical'
            ],
            'Retail': [
                'retail', 'ecommerce', 'shopping', 'store',
                'flipkart', 'amazon', 'consumer', 'marketplace'
            ]
        }
        
        # Check entities first
        if entities.get('government_bodies'):
            return 'Government'
        elif entities.get('companies'):
            # Check if it's a known IT company
            it_companies = ['infosys', 'tcs', 'wipro', 'hcl', 'tech mahindra']
            if any(company.lower() in [c.lower() for c in entities['companies']] 
                   for company in it_companies):
                return 'IT & Software'
        
        # Check text content for sector keywords
        sector_scores = {}
        for sector, keywords in sector_keywords.items():
            score = sum(1 for keyword in keywords if keyword in text_lower)
            if score > 0:
                sector_scores[sector] = score
        
        if sector_scores:
            return max(sector_scores.items(), key=lambda x: x[1])[0]
        
        return 'Other'
    
    def _identify_apt_group(self, text: str, threat_indicators: Dict) -> Optional[str]:
        """
        Identify potential APT group from text content
        
        Args:
            text: Incident text content
            threat_indicators: Dictionary of threat indicators
            
        Returns:
            Identified APT group or None
        """
        # Check threat indicators first
        if threat_indicators.get('apt_groups'):
            return threat_indicators['apt_groups'][0]
        
        text_lower = text.lower()
        
        # Known APT groups and their indicators
        apt_indicators = {
            'Lazarus Group': ['lazarus', 'hidden cobra', 'north korea', 'dprk'],
            'APT1': ['apt1', 'comment crew', 'pla unit 61398'],
            'APT29': ['apt29', 'cozy bear', 'the dukes'],
            'APT40': ['apt40', 'leviathan', 'muddy water'],
            'Sidewinder': ['sidewinder', 'rattlesnake', 'south asia'],
            'Patchwork': ['patchwork', 'dropping elephant', 'chinastrats'],
            'Confucius': ['confucius', 'south asia', 'education sector'],
            'Transparent Tribe': ['transparent tribe', 'apt36', 'mythic leopard']
        }
        
        for apt_group, indicators in apt_indicators.items():
            if any(indicator in text_lower for indicator in indicators):
                return apt_group
        
        return None
    
    def process_batch(self, incident_ids: List[int]) -> Dict[str, Any]:
        """
        Process a batch of incidents for classification
        
        Args:
            incident_ids: List of incident IDs to process
            
        Returns:
            Dictionary with processing results
        """
        results = {
            'processed_count': 0,
            'relevant_count': 0,
            'error_count': 0,
            'errors': []
        }
        
        try:
            with db_manager.get_session() as session:
                from database.models import Incident
                
                for incident_id in incident_ids:
                    try:
                        incident = session.query(Incident).get(incident_id)
                        if not incident:
                            continue
                        
                        # Prepare incident data for classification
                        incident_data = {
                            'title': incident.title,
                            'description': incident.description,
                            'url': incident.url,
                            'source_id': incident.source_id
                        }
                        
                        # Classify incident
                        enhanced_data = self.classify_incident(incident_data)
                        
                        # Update incident in database
                        incident.relevance_score = enhanced_data['relevance_score']
                        incident.is_relevant = enhanced_data['is_relevant']
                        incident.india_related = enhanced_data['india_related']
                        incident.category = enhanced_data['category']
                        incident.severity = enhanced_data['severity']
                        incident.affected_sector = enhanced_data['affected_sector']
                        incident.indian_entities = enhanced_data.get('indian_entities')
                        incident.attack_vectors = enhanced_data.get('attack_vectors')
                        incident.iocs = enhanced_data.get('iocs')
                        incident.apt_group = enhanced_data.get('apt_group')
                        incident.processed = True
                        incident.updated_at = datetime.utcnow()
                        
                        results['processed_count'] += 1
                        if enhanced_data['is_relevant']:
                            results['relevant_count'] += 1
                        
                    except Exception as e:
                        error_msg = f"Error processing incident {incident_id}: {str(e)}"
                        results['errors'].append(error_msg)
                        results['error_count'] += 1
                        logger.error(error_msg)
                
                session.commit()
        
        except Exception as e:
            logger.error(f"Batch processing failed: {e}")
            results['errors'].append(f"Batch processing error: {str(e)}")
        
        return results
    
    def process_unprocessed_incidents(self, limit: int = 100) -> Dict[str, Any]:
        """
        Process all unprocessed incidents in the database
        
        Args:
            limit: Maximum number of incidents to process
            
        Returns:
            Dictionary with processing results
        """
        with db_manager.get_session() as session:
            from database.models import Incident
            
            unprocessed_incidents = session.query(Incident).filter(
                Incident.processed == False
            ).limit(limit).all()
            
            if not unprocessed_incidents:
                logger.info("No unprocessed incidents found")
                return {'processed_count': 0, 'relevant_count': 0, 'error_count': 0}
            
            logger.info(f"Processing {len(unprocessed_incidents)} unprocessed incidents")
            
            results = {
                'processed_count': 0,
                'relevant_count': 0,
                'error_count': 0,
                'errors': []
            }
            
            for incident in unprocessed_incidents:
                try:
                    # Prepare incident data for classification
                    incident_data = {
                        'title': incident.title,
                        'description': incident.description,
                        'url': incident.url,
                        'source_id': incident.source_id
                    }
                    
                    # Classify the incident
                    classification = self.classify_incident(incident_data)
                    
                    # Update incident with classification results
                    incident.relevance_score = classification['relevance_score']
                    incident.is_relevant = classification['is_relevant']
                    incident.india_related = classification['is_relevant']
                    incident.processed = True
                    
                    if classification.get('category'):
                        incident.category = classification['category']
                    if classification.get('severity'):
                        incident.severity = classification['severity']
                    
                    incident.updated_at = datetime.utcnow()
                    
                    results['processed_count'] += 1
                    if classification['is_relevant']:
                        results['relevant_count'] += 1
                        
                except Exception as e:
                    error_msg = f"Error processing incident {incident.id}: {str(e)}"
                    results['errors'].append(error_msg)
                    results['error_count'] += 1
                    logger.error(error_msg)
            
            logger.info(f"Batch processing completed: {results['processed_count']} processed, "
                       f"{results['relevant_count']} relevant, {results['error_count']} errors")
            
            return results

# Global predictor instance
predictor = IncidentPredictor()

def classify_single_incident(incident_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Classify a single incident (convenience function)
    
    Args:
        incident_data: Dictionary containing incident information
        
    Returns:
        Enhanced incident data with classification results
    """
    return predictor.classify_incident(incident_data)

def process_all_unprocessed() -> Dict[str, Any]:
    """
    Process all unprocessed incidents (convenience function)
    
    Returns:
        Dictionary with processing results
    """
    return predictor.process_unprocessed_incidents()

def main():
    """Main function for testing the predictor"""
    # Test with sample incidents
    test_incidents = [
        {
            'title': 'AIIMS Delhi hit by ransomware attack',
            'description': 'Major government hospital in New Delhi faces cyber attack affecting patient records and hospital operations',
            'url': 'https://example.com/aiims-attack',
            'source_id': 1
        },
        {
            'title': 'US company reports data breach',
            'description': 'American tech company discovers unauthorized access to customer database',
            'url': 'https://example.com/us-breach',
            'source_id': 1
        }
    ]
    
    print("Testing Incident Predictor:")
    for i, incident in enumerate(test_incidents, 1):
        print(f"\n--- Test Incident {i} ---")
        result = classify_single_incident(incident)
        print(f"Title: {result['title']}")
        print(f"Relevant: {result.get('is_relevant', False)}")
        print(f"Confidence: {result.get('relevance_score', 0):.3f}")
        print(f"Category: {result.get('category', 'Unknown')}")
        print(f"Severity: {result.get('severity', 'Unknown')}")
        print(f"Sector: {result.get('affected_sector', 'Unknown')}")

if __name__ == "__main__":
    main()


