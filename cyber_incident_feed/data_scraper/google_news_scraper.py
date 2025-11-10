"""
Google News scraper for cybersecurity news
Improved version using RSS feeds for reliable scraping
"""
import feedparser
import logging
import time
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from urllib.parse import quote_plus, urlparse
import random

from config import (
    USER_AGENTS, REQUEST_TIMEOUT, REQUEST_DELAY, MAX_RETRIES,
    INDIA_CYBER_KEYWORDS, SECURITY_CONFIG
)
from database.db_setup import db_manager
from database.models import Source

logger = logging.getLogger(__name__)


class GoogleNewsScraperError(Exception):
    """Custom exception for Google News scraping errors"""
    pass


class GoogleNewsScraper:
    """
    Improved scraper for Google News cybersecurity articles using RSS feeds
    """

    def __init__(self):
        """Initialize the Google News scraper"""
        self.base_url = "https://news.google.com"
        
    def _parse_rss_date(self, date_str: str) -> Optional[datetime]:
        """Parse date string from RSS feed format"""
        try:
            # Try standard RSS date formats
            date_formats = [
                "%a, %d %b %Y %H:%M:%S %Z",
                "%a, %d %b %Y %H:%M:%S %z",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%d %H:%M:%S",
                "%d %b %Y %H:%M:%S",
                "%B %d, %Y",
                "%d %b %Y"
            ]
            
            for fmt in date_formats:
                try:
                    return datetime.strptime(date_str.strip(), fmt)
                except ValueError:
                    continue
            
            # Try feedparser's date parsing
            try:
                # feedparser parses dates automatically in entries, but we can try manual parsing
                from email.utils import parsedate_tz
                parsed = parsedate_tz(date_str)
                if parsed:
                    # Convert to datetime (simplified)
                    import time
                    timestamp = time.mktime(parsed[:9])
                    return datetime.fromtimestamp(timestamp)
            except Exception:
                pass
                
        except Exception as e:
            logger.debug(f"Failed to parse date '{date_str}': {e}")
        
        return None

    def _extract_keywords(self, text: str) -> List[str]:
        """Extract relevant cybersecurity keywords from text"""
        keywords = []
        text_lower = text.lower()

        important_terms = [
            'vulnerability', 'exploit', 'malware', 'ransomware', 'phishing',
            'ddos', 'apt', 'zero-day', 'backdoor', 'trojan', 'spyware',
            'adware', 'botnet', 'crypto', 'blockchain', 'financial',
            'banking', 'healthcare', 'government', 'critical infrastructure',
            'supply chain', 'iot', 'industrial control', 'scada',
            'cyber attack', 'data breach', 'security breach', 'hack',
            'cybersecurity', 'cybercrime', 'threat', 'incident', 'hacking',
            'data leak', 'cyber fraud', 'online fraud', 'security incident',
            'cyber threat', 'security vulnerability', 'cyber defense'
        ]

        for term in important_terms:
            if term in text_lower:
                keywords.append(term)

        return list(set(keywords))[:15]  # Remove duplicates and limit

    def _is_india_related(self, text: str, source_url: str = "") -> bool:
        """
        Improved India-related detection - more lenient and intelligent
        Returns True if content is likely related to Indian cybersecurity
        """
        if not text:
            return False
            
        text_lower = text.lower()
        url_lower = source_url.lower() if source_url else ""
        
        # Strong Indian indicators
        strong_indian_indicators = [
            'india', 'indian', 'bharat', 'hindustan',
            'delhi', 'mumbai', 'bangalore', 'bengaluru', 'hyderabad',
            'chennai', 'madras', 'pune', 'kolkata', 'calcutta',
            'ahmedabad', 'surat', 'jaipur', 'lucknow', 'kanpur',
            'nagpur', 'indore', 'thane', 'bhopal', 'visakhapatnam',
            'patna', 'vadodara', 'ghaziabad', 'ludhiana', 'agra',
            'aadhaar', 'aadhar', 'digital india', 'make in india',
            'government of india', 'indian government', 'goi',
            'ministry of', 'pm modi', 'prime minister',
            'cert-in', 'indian computer emergency response team',
            'meity', 'ministry of electronics', 'nitiaayog',
            'rbi', 'reserve bank of india', 'sebi', 'irdai'
        ]
        
        # Indian companies and organizations
        indian_entities = [
            'infosys', 'tcs', 'tata consultancy', 'wipro', 'tech mahindra',
            'hcl', 'cognizant india', 'accenture india', 'capgemini india',
            'state bank of india', 'sbi', 'icici', 'hdfc', 'axis bank',
            'kotak mahindra', 'pnb', 'bank of baroda', 'canara bank',
            'paytm', 'phonepe', 'google pay india', 'amazon pay india',
            'flipkart', 'amazon india', 'reliance', 'jio', 'airtel',
            'vodafone idea', 'bsnl', 'mtnl', 'tata communications',
            'indian railways', 'air india', 'indigo', 'spicejet'
        ]
        
        # Indian states and regions
        indian_states = [
            'andhra pradesh', 'arunachal pradesh', 'assam', 'bihar',
            'chhattisgarh', 'goa', 'gujarat', 'haryana', 'himachal pradesh',
            'jharkhand', 'karnataka', 'kerala', 'madhya pradesh',
            'maharashtra', 'manipur', 'meghalaya', 'mizoram', 'nagaland',
            'odisha', 'punjab', 'rajasthan', 'sikkim', 'tamil nadu',
            'telangana', 'tripura', 'uttar pradesh', 'uttarakhand',
            'west bengal', 'delhi ncr', 'ncr', 'noida', 'gurgaon'
        ]
        
        # Cyber security keywords (broader list)
        cyber_keywords = [
            'cyber attack', 'data breach', 'ransomware', 'phishing',
            'malware', 'hacking', 'cybersecurity', 'security breach',
            'data leak', 'cyber crime', 'cybercrime', 'vulnerability',
            'exploit', 'hack', 'hacked', 'breach', 'leak', 'compromised',
            'cyber threat', 'security incident', 'cyber fraud',
            'online fraud', 'digital fraud', 'cyber security',
            'information security', 'network security', 'data security',
            'cyber defense', 'cyber intelligence', 'threat intelligence'
        ]
        
        # Check URL for Indian domains
        indian_domains = [
            '.in', '.co.in', '.gov.in', '.ac.in', '.edu.in',
            'timesofindia', 'thehindu', 'indianexpress', 'hindustantimes',
            'ndtv', 'news18', 'firstpost', 'moneycontrol', 'livemint',
            'economictimes', 'business-standard', 'techcrunch india'
        ]
        
        url_score = sum(1 for domain in indian_domains if domain in url_lower)
        
        # Count indicators
        india_score = sum(1 for indicator in strong_indian_indicators if indicator in text_lower)
        india_score += sum(1 for entity in indian_entities if entity in text_lower)
        india_score += sum(1 for state in indian_states if state in text_lower)
        cyber_score = sum(1 for keyword in cyber_keywords if keyword in text_lower)
        
        # More lenient detection:
        # 1. If URL is from Indian domain, require only cyber keyword
        # 2. If strong India indicator found, require only cyber keyword
        # 3. Otherwise, require both India and cyber indicators
        
        if url_score > 0 and cyber_score > 0:
            return True
        
        if india_score >= 2 and cyber_score > 0:
            return True
            
        if india_score > 0 and cyber_score >= 2:
            return True
        
        # For RSS feeds from Indian sources, be more lenient
        if any(domain in url_lower for domain in ['.in', 'indian', 'india']):
            if cyber_score > 0 or any(keyword in text_lower for keyword in ['security', 'cyber', 'hack', 'breach', 'attack']):
                return True
        
        return False

    def _classify_severity(self, title: str, content: str) -> str:
        """Classify incident severity based on content"""
        text = f"{title} {content}".lower()
        
        critical_indicators = [
            'critical', 'zero-day', 'remote code execution', 'rce',
            'privilege escalation', 'system compromise', 'nation-state',
            'apt', 'advanced persistent threat', 'state-sponsored',
            'critical infrastructure', 'power grid', 'financial system',
            'government breach', 'massive breach', 'millions affected'
        ]
        
        high_indicators = [
            'high', 'severe', 'serious', 'major', 'significant',
            'vulnerability', 'exploit', 'malware', 'ransomware',
            'phishing', 'ddos', 'attack', 'breach', 'data breach',
            'hacked', 'compromised', 'leaked'
        ]
        
        medium_indicators = [
            'medium', 'moderate', 'security', 'advisory', 'update',
            'patch', 'fix', 'warning', 'alert', 'incident'
        ]
        
        if any(indicator in text for indicator in critical_indicators):
            return 'Critical'
        elif any(indicator in text for indicator in high_indicators):
            return 'High'
        elif any(indicator in text for indicator in medium_indicators):
            return 'Medium'
        else:
            return 'Low'

    def _classify_category(self, title: str, content: str) -> str:
        """Classify incident category"""
        text = f"{title} {content}".lower()
        
        category_keywords = {
            'Data Breach': ['data breach', 'data leak', 'personal data', 'customer data', 'user data exposed'],
            'Ransomware': ['ransomware', 'ransom', 'locked', 'encrypted files'],
            'Phishing': ['phishing', 'phishing attack', 'email scam', 'fraudulent email'],
            'Malware': ['malware', 'virus', 'trojan', 'spyware', 'adware', 'botnet'],
            'DDoS Attack': ['ddos', 'distributed denial', 'service attack', 'server down'],
            'Vulnerability': ['vulnerability', 'cve-', 'security flaw', 'bug', 'exploit'],
            'APT Campaign': ['apt', 'advanced persistent threat', 'nation-state', 'state-sponsored'],
            'Supply Chain Attack': ['supply chain', 'third-party', 'vendor breach'],
            'Insider Threat': ['insider', 'employee', 'internal threat'],
            'Social Engineering': ['social engineering', 'scam', 'fraud', 'impersonation']
        }
        
        for category, keywords in category_keywords.items():
            if any(keyword in text for keyword in keywords):
                return category
        
        return 'Other'

    def _classify_affected_sector(self, title: str, content: str) -> str:
        """Classify affected sector"""
        text = f"{title} {content}".lower()
        
        sector_keywords = {
            'Banking & Finance': ['bank', 'financial', 'fintech', 'payment', 'upi', 'wallet', 'rbi', 'banking'],
            'Government': ['government', 'ministry', 'department', 'public sector', 'govt', 'goi'],
            'Healthcare': ['healthcare', 'hospital', 'medical', 'health', 'patient data'],
            'Education': ['education', 'university', 'school', 'college', 'student'],
            'IT & Software': ['it company', 'software', 'tech company', 'it services', 'outsourcing'],
            'Telecommunications': ['telecom', 'communication', 'mobile', 'network', '5g', '4g'],
            'Energy': ['energy', 'power', 'utility', 'electricity', 'grid'],
            'Transportation': ['transport', 'railways', 'airlines', 'aviation', 'logistics'],
            'E-commerce': ['e-commerce', 'online shopping', 'ecommerce', 'retail online'],
            'Manufacturing': ['manufacturing', 'factory', 'industrial', 'production']
        }
        
        for sector, keywords in sector_keywords.items():
            if any(keyword in text for keyword in keywords):
                return sector
        
        return 'Other'

    def scrape_google_news_rss(self, query: str, max_results: int = 50, source_id: int = None) -> List[Dict[str, Any]]:
        """
        Scrape Google News RSS feed for a specific query
        This is more reliable than HTML scraping
        """
        articles = []
        
        try:
            # Construct Google News RSS URL
            encoded_query = quote_plus(query.strip())
            rss_url = f"https://news.google.com/rss/search?q={encoded_query}&hl=en-IN&gl=IN&ceid=IN:en&num={max_results}"
            
            logger.info(f"Scraping Google News RSS for query: {query}")
            
            # Parse RSS feed
            feed = feedparser.parse(rss_url)
            
            if feed.bozo and feed.bozo_exception:
                logger.warning(f"RSS feed parse warning: {feed.bozo_exception}")
            
            if not feed.entries:
                logger.warning(f"No entries found in RSS feed for query: {query}")
                return articles
            
            for entry in feed.entries[:max_results]:
                try:
                    # Parse publication date
                    pub_date = None
                    if hasattr(entry, 'published_parsed') and entry.published_parsed:
                        pub_date = datetime(*entry.published_parsed[:6])
                    elif hasattr(entry, 'published'):
                        pub_date = self._parse_rss_date(entry.published)
                    elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
                        pub_date = datetime(*entry.updated_parsed[:6])
                    
                    # Skip very old articles (older than 60 days for better coverage)
                    if pub_date and (datetime.now() - pub_date).days > 60:
                        continue
                    
                    # Extract content
                    title = entry.get('title', '').strip()
                    if not title or len(title) < 10:
                        continue
                    
                    # Get description/summary
                    description = ""
                    if hasattr(entry, 'summary'):
                        description = entry.summary
                    elif hasattr(entry, 'description'):
                        description = entry.description
                    elif hasattr(entry, 'content') and entry.content:
                        description = entry.content[0].get('value', '') if isinstance(entry.content, list) else str(entry.content)
                    
                    # Clean HTML from description
                    if description:
                        # Remove HTML tags
                        description = re.sub(r'<[^>]+>', '', description)
                        description = description.strip()
                    
                    # Get link
                    link = entry.get('link', '')
                    if not link:
                        continue
                    
                    # Combine text for analysis
                    full_text = f"{title} {description}".strip()
                    
                    # Check if India-related (more lenient for RSS feeds)
                    if not self._is_india_related(full_text, link):
                        continue
                    
                    # Extract keywords
                    keywords = self._extract_keywords(full_text)
                    
                    # Classify
                    severity = self._classify_severity(title, description)
                    category = self._classify_category(title, description)
                    affected_sector = self._classify_affected_sector(title, description)
                    
                    # Create article dictionary
                    article = {
                        'title': title,
                        'url': link,
                        'description': description[:2000] if description else title,  # Limit description length
                        'incident_date': pub_date,
                        'source_id': source_id,
                        'keywords': keywords,
                        'summary': description[:500] if description else title,
                        'india_related': True,
                        'category': category,
                        'severity': severity,
                        'affected_sector': affected_sector,
                    }
                    
                    articles.append(article)
                    
                except Exception as e:
                    logger.error(f"Error processing RSS entry: {e}")
                    logger.debug(f"Entry data: {entry.get('title', 'No title')}")
                    continue
            
            logger.info(f"Found {len(articles)} India-related articles for query: {query}")
            
        except Exception as e:
            logger.error(f"Failed to scrape Google News RSS for query '{query}': {e}")
            import traceback
            logger.debug(traceback.format_exc())
        
        return articles

    def _get_google_news_source_id(self) -> Optional[int]:
        """Get Google News source ID from database"""
        try:
            with db_manager.get_session() as session:
                source = session.query(Source).filter(
                    Source.name == "Google News India Cyber"
                ).first()
                
                if source:
                    return source.id
                else:
                    logger.warning("Google News source not found in database")
                    return None
        except Exception as e:
            logger.error(f"Error getting Google News source ID: {e}")
            return None

    def scrape_cybersecurity_news(self, max_results_per_query: int = 30, source_id: int = None) -> Dict[str, Any]:
        """
        Scrape cybersecurity news from Google News using multiple queries
        Improved version with better error handling and deduplication
        """
        results = {
            'total_articles': 0,
            'india_related': 0,
            'queries_processed': 0,
            'errors': []
        }
        
        all_articles = []
        seen_urls = set()  # Global deduplication
        
        # Get source ID if not provided
        if source_id is None:
            source_id = self._get_google_news_source_id()
        
        try:
            # Use keywords from config - focus on most relevant ones
            search_queries = INDIA_CYBER_KEYWORDS[:15]  # Use top 15 keywords
            
            logger.info(f"Starting Google News scraping with {len(search_queries)} queries")
            
            for query in search_queries:
                try:
                    logger.info(f"Processing query: {query}")
                    articles = self.scrape_google_news_rss(query, max_results_per_query, source_id)
                    
                    # Deduplicate by URL
                    unique_articles = []
                    for article in articles:
                        url = article.get('url', '')
                        if url and url not in seen_urls:
                            seen_urls.add(url)
                            unique_articles.append(article)
                    
                    all_articles.extend(unique_articles)
                    results['queries_processed'] += 1
                    
                    logger.info(f"Query '{query}': {len(unique_articles)} unique articles (total: {len(all_articles)})")
                    
                    # Delay between queries to avoid rate limiting
                    time.sleep(REQUEST_DELAY * 2)
                    
                except Exception as e:
                    error_msg = f"Error processing query '{query}': {str(e)}"
                    results['errors'].append(error_msg)
                    logger.error(error_msg)
                    import traceback
                    logger.debug(traceback.format_exc())
                    continue
            
            # Save articles to database
            saved_count = 0
            if all_articles:
                logger.info(f"Saving {len(all_articles)} articles to database...")
                for article in all_articles:
                    try:
                        if db_manager.add_incident(article):
                            saved_count += 1
                    except Exception as e:
                        logger.error(f"Error saving article '{article.get('title', 'Unknown')}': {e}")
                        continue
                
                # Log activity
                if source_id:
                    try:
                        db_manager.log_scraping_activity(
                            source_id=source_id,
                            status='success',
                            items_found=len(all_articles),
                            items_processed=saved_count,
                            processing_time=0
                        )
                    except Exception as e:
                        logger.error(f"Error logging scraping activity: {e}")
            
            results['total_articles'] = len(all_articles)
            results['india_related'] = len([a for a in all_articles if a.get('india_related')])
            
            logger.info(f"Google News scraping completed: {len(all_articles)} articles found, {saved_count} saved")
            
        except Exception as e:
            error_msg = f"Google News scraping error: {str(e)}"
            results['errors'].append(error_msg)
            logger.error(error_msg)
            import traceback
            logger.debug(traceback.format_exc())
        
        return results


def main():
    """Main function for testing the Google News scraper"""
    scraper = GoogleNewsScraper()
    results = scraper.scrape_cybersecurity_news()
    
    print("Google News Scraping Results:")
    print(f"Total articles: {results['total_articles']}")
    print(f"India-related: {results['india_related']}")
    print(f"Queries processed: {results['queries_processed']}")
    
    if results['errors']:
        print(f"Errors: {len(results['errors'])}")
        for error in results['errors']:
            print(f"  - {error}")


if __name__ == "__main__":
    main()
