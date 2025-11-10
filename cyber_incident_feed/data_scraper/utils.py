"""
Utility functions for data scraping operations
"""
import re
import logging
import hashlib
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup

from config import SECURITY_CONFIG, INDIA_CYBER_KEYWORDS

logger = logging.getLogger(__name__)

class TextProcessor:
    """
    Utility class for text processing and analysis
    """
    
    @staticmethod
    def clean_text(text: str) -> str:
        """
        Clean and normalize text content
        
        Args:
            text: Raw text to clean
            
        Returns:
            Cleaned text
        """
        if not text:
            return ""
        
        # Remove extra whitespace and normalize
        text = re.sub(r'\s+', ' ', text.strip())
        
        # Remove special characters but keep basic punctuation
        text = re.sub(r'[^\w\s.,!?;:()\-\'\"@#$%&*+/=<>[\]{}|~`]', '', text)
        
        # Remove excessively long words (likely garbage)
        words = text.split()
        cleaned_words = [word for word in words if len(word) <= 50]
        
        return ' '.join(cleaned_words)
    
    @staticmethod
    def extract_entities(text: str) -> Dict[str, List[str]]:
        """
        Extract Indian entities and organizations from text
        
        Args:
            text: Text to analyze
            
        Returns:
            Dictionary with extracted entities
        """
        entities = {
            'organizations': [],
            'locations': [],
            'government_bodies': [],
            'companies': []
        }
        
        text_lower = text.lower()
        
        # Indian organizations and companies
        organizations = [
            'infosys', 'tcs', 'wipro', 'hcl technologies', 'tech mahindra',
            'cognizant', 'mindtree', 'l&t infotech', 'mphasis', 'hexaware',
            'cyient', 'persistent systems', 'sonata software'
        ]
        
        # Indian government bodies
        govt_bodies = [
            'cert-in', 'government of india', 'ministry of electronics',
            'department of telecommunications', 'reserve bank of india',
            'sebi', 'irda', 'npci', 'uidai'
        ]
        
        # Indian cities and states
        locations = [
            'mumbai', 'delhi', 'bangalore', 'hyderabad', 'chennai', 'pune',
            'kolkata', 'ahmedabad', 'surat', 'jaipur', 'lucknow', 'kanpur',
            'nagpur', 'indore', 'thane', 'bhopal', 'visakhapatnam', 'pimpri-chinchwad',
            'patna', 'vadodara', 'ghaziabad', 'ludhiana', 'agra', 'nashik'
        ]
        
        # Banks and financial institutions
        financial_orgs = [
            'state bank of india', 'sbi', 'icici bank', 'hdfc bank',
            'axis bank', 'kotak mahindra bank', 'yes bank', 'indusind bank',
            'punjab national bank', 'bank of baroda', 'canara bank',
            'union bank', 'indian bank', 'paytm', 'phonepe', 'google pay',
            'bharatpe', 'razorpay', 'cashfree'
        ]
        
        # Extract entities
        for org in organizations:
            if org in text_lower:
                entities['organizations'].append(org.title())
        
        for govt in govt_bodies:
            if govt in text_lower:
                entities['government_bodies'].append(govt.upper() if govt.startswith('cert') else govt.title())
        
        for loc in locations:
            if loc in text_lower:
                entities['locations'].append(loc.title())
        
        for fin_org in financial_orgs:
            if fin_org in text_lower:
                entities['companies'].append(fin_org.title())
        
        return entities
    
    @staticmethod
    def calculate_india_relevance_score(text: str) -> float:
        """
        Calculate relevance score for Indian cybersecurity content
        
        Args:
            text: Text to analyze
            
        Returns:
            Relevance score between 0 and 1
        """
        if not text:
            return 0.0
        
        text_lower = text.lower()
        score = 0.0
        
        # India indicators with weights
        india_indicators = {
            'india': 0.3, 'indian': 0.3, 'delhi': 0.2, 'mumbai': 0.2,
            'bangalore': 0.2, 'hyderabad': 0.2, 'chennai': 0.2, 'pune': 0.2,
            'aadhaar': 0.4, 'digital india': 0.4, 'government of india': 0.4,
            'indian government': 0.3, 'cert-in': 0.5, 'indian companies': 0.3,
            'indian banks': 0.3, 'upi': 0.3, 'paytm': 0.2, 'phonepe': 0.2,
            'tcs': 0.2, 'infosys': 0.2, 'wipro': 0.2
        }
        
        # Cybersecurity indicators with weights
        cyber_indicators = {
            'cyber attack': 0.4, 'data breach': 0.4, 'ransomware': 0.4,
            'phishing': 0.3, 'malware': 0.3, 'hacking': 0.3, 'vulnerability': 0.3,
            'cybersecurity': 0.3, 'security breach': 0.4, 'data leak': 0.4,
            'cyber crime': 0.4, 'ddos': 0.3, 'apt': 0.3, 'exploit': 0.3
        }
        
        # Calculate India context score
        india_score = 0.0
        for indicator, weight in india_indicators.items():
            if indicator in text_lower:
                india_score += weight
        
        # Calculate cyber context score
        cyber_score = 0.0
        for indicator, weight in cyber_indicators.items():
            if indicator in text_lower:
                cyber_score += weight
        
        # Normalize scores
        india_score = min(india_score, 1.0)
        cyber_score = min(cyber_score, 1.0)
        
        # Combined score (both contexts needed)
        if india_score > 0 and cyber_score > 0:
            score = (india_score * cyber_score) ** 0.5  # Geometric mean
        
        return min(score, 1.0)

class URLValidator:
    """
    Utility class for URL validation and security checks
    """
    
    @staticmethod
    def is_valid_url(url: str) -> bool:
        """
        Check if URL is valid and secure
        
        Args:
            url: URL to validate
            
        Returns:
            True if valid, False otherwise
        """
        try:
            parsed = urlparse(url)
            
            # Check basic URL structure
            if not parsed.scheme or not parsed.netloc:
                return False
            
            # Check URL length
            if len(url) > SECURITY_CONFIG['max_url_length']:
                return False
            
            # Check for dangerous protocols
            if parsed.scheme.lower() not in ['http', 'https']:
                return False
            
            return True
            
        except Exception:
            return False
    
    @staticmethod
    def is_allowed_domain(url: str) -> bool:
        """
        Check if domain is in allowed list
        
        Args:
            url: URL to check
            
        Returns:
            True if allowed, False otherwise
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Remove www prefix
            if domain.startswith('www.'):
                domain = domain[4:]
            
            return domain in SECURITY_CONFIG['allowed_domains']
            
        except Exception:
            return False
    
    @staticmethod
    def normalize_url(url: str, base_url: str = None) -> str:
        """
        Normalize and clean URL
        
        Args:
            url: URL to normalize
            base_url: Base URL for relative links
            
        Returns:
            Normalized URL
        """
        try:
            # Handle relative URLs
            if base_url and not url.startswith(('http://', 'https://')):
                url = urljoin(base_url, url)
            
            # Parse and rebuild URL
            parsed = urlparse(url)
            
            # Remove fragment and some query parameters
            normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            if parsed.query:
                # Keep important query parameters, remove tracking ones
                important_params = ['q', 'search', 'id', 'page', 'category']
                query_parts = parsed.query.split('&')
                filtered_parts = []
                
                for part in query_parts:
                    if '=' in part:
                        key = part.split('=')[0].lower()
                        if key in important_params:
                            filtered_parts.append(part)
                
                if filtered_parts:
                    normalized += '?' + '&'.join(filtered_parts)
            
            return normalized
            
        except Exception:
            return url

class ContentDeduplicator:
    """
    Utility class for detecting and handling duplicate content
    """
    
    def __init__(self):
        """Initialize deduplicator"""
        self.seen_hashes: Set[str] = set()
        self.url_cache: Set[str] = set()
    
    def get_content_hash(self, content: str) -> str:
        """
        Generate hash for content deduplication
        
        Args:
            content: Content to hash
            
        Returns:
            Content hash
        """
        # Normalize content for hashing
        normalized = re.sub(r'\s+', ' ', content.lower().strip())
        normalized = re.sub(r'[^\w\s]', '', normalized)
        
        # Generate hash
        return hashlib.md5(normalized.encode('utf-8')).hexdigest()
    
    def is_duplicate_content(self, content: str) -> bool:
        """
        Check if content is duplicate
        
        Args:
            content: Content to check
            
        Returns:
            True if duplicate, False otherwise
        """
        content_hash = self.get_content_hash(content)
        
        if content_hash in self.seen_hashes:
            return True
        
        self.seen_hashes.add(content_hash)
        return False
    
    def is_duplicate_url(self, url: str) -> bool:
        """
        Check if URL has been seen before
        
        Args:
            url: URL to check
            
        Returns:
            True if duplicate, False otherwise
        """
        normalized_url = URLValidator.normalize_url(url)
        
        if normalized_url in self.url_cache:
            return True
        
        self.url_cache.add(normalized_url)
        return False

class SecurityValidator:
    """
    Security validation utilities for scraped content
    """
    
    @staticmethod
    def sanitize_html(html_content: str) -> str:
        """
        Sanitize HTML content to prevent XSS
        
        Args:
            html_content: Raw HTML content
            
        Returns:
            Sanitized HTML
        """
        if not SECURITY_CONFIG['sanitize_html']:
            return html_content
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Remove dangerous tags
            dangerous_tags = ['script', 'iframe', 'object', 'embed', 'form', 'input']
            for tag in dangerous_tags:
                for elem in soup.find_all(tag):
                    elem.decompose()
            
            # Remove dangerous attributes
            for tag in soup.find_all():
                dangerous_attrs = ['onclick', 'onload', 'onerror', 'onmouseover', 'onfocus']
                for attr in dangerous_attrs:
                    if tag.has_attr(attr):
                        del tag[attr]
            
            return str(soup)
            
        except Exception as e:
            logger.error(f"Failed to sanitize HTML: {e}")
            return ""
    
    @staticmethod
    def validate_content_safety(content: str) -> bool:
        """
        Validate content for safety (no malicious patterns)
        
        Args:
            content: Content to validate
            
        Returns:
            True if safe, False otherwise
        """
        if not content:
            return True
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'<script.*?>.*?</script>',
            r'javascript:',
            r'data:text/html',
            r'vbscript:',
            r'onload\s*=',
            r'onerror\s*=',
        ]
        
        content_lower = content.lower()
        
        for pattern in suspicious_patterns:
            if re.search(pattern, content_lower, re.IGNORECASE | re.DOTALL):
                logger.warning(f"Suspicious pattern detected: {pattern}")
                return False
        
        return True

def format_incident_summary(title: str, content: str, source: str, max_length: int = 300) -> str:
    """
    Format incident summary for display
    
    Args:
        title: Incident title
        content: Incident content
        source: Source name
        max_length: Maximum summary length
        
    Returns:
        Formatted summary
    """
    # Start with title
    summary = title
    
    if content and len(summary) < max_length - 50:
        # Add content if there's space
        clean_content = TextProcessor.clean_text(content)
        available_space = max_length - len(summary) - 20  # Leave space for source
        
        if len(clean_content) > available_space:
            clean_content = clean_content[:available_space] + "..."
        
        summary += f" - {clean_content}"
    
    # Add source information
    if len(summary) < max_length - 20:
        summary += f" [Source: {source}]"
    
    return summary[:max_length]

def extract_threat_indicators(text: str) -> Dict[str, List[str]]:
    """
    Extract threat indicators from text
    
    Args:
        text: Text to analyze
        
    Returns:
        Dictionary with threat indicators
    """
    indicators = {
        'malware_families': [],
        'attack_techniques': [],
        'iocs': [],
        'apt_groups': []
    }
    
    text_lower = text.lower()
    
    # Known malware families
    malware_families = [
        'wannacry', 'petya', 'notpetya', 'ryuk', 'maze', 'conti', 'lockbit',
        'emotet', 'trickbot', 'qakbot', 'dridex', 'zloader', 'icedid'
    ]
    
    # Attack techniques
    attack_techniques = [
        'spear phishing', 'watering hole', 'supply chain', 'lateral movement',
        'privilege escalation', 'credential dumping', 'remote access',
        'command and control', 'data exfiltration', 'backdoor'
    ]
    
    # APT groups
    apt_groups = [
        'lazarus', 'apt1', 'apt28', 'apt29', 'apt40', 'sidewinder',
        'patchwork', 'confucius', 'transparent tribe'
    ]
    
    # Extract indicators
    for family in malware_families:
        if family in text_lower:
            indicators['malware_families'].append(family.title())
    
    for technique in attack_techniques:
        if technique in text_lower:
            indicators['attack_techniques'].append(technique.title())
    
    for group in apt_groups:
        if group in text_lower:
            indicators['apt_groups'].append(group.upper())
    
    # Extract basic IOCs (simplified)
    # IP addresses
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = re.findall(ip_pattern, text)
    if ips:
        indicators['iocs'].extend([f"IP: {ip}" for ip in ips[:5]])  # Limit to 5
    
    # URLs (basic pattern)
    url_pattern = r'https?://[^\s<>"]+[^\s<>".,)]'
    urls = re.findall(url_pattern, text)
    if urls:
        indicators['iocs'].extend([f"URL: {url}" for url in urls[:3]])  # Limit to 3
    
    return indicators

