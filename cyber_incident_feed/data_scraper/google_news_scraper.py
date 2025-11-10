"""
Google News scraper for cybersecurity news
Scrapes news from Google News search results for cybersecurity topics
"""
import requests
import logging
import time
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, quote
import random
import json

from config import (
    USER_AGENTS, REQUEST_TIMEOUT, REQUEST_DELAY, MAX_RETRIES,
    INDIA_CYBER_KEYWORDS, SECURITY_CONFIG
)
from database.db_setup import db_manager

logger = logging.getLogger(__name__)


class GoogleNewsScraperError(Exception):
    """Custom exception for Google News scraping errors"""
    pass


class GoogleNewsScraper:
    """
    Scraper for Google News cybersecurity articles
    """

    def __init__(self):
        """Initialize the Google News scraper"""
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        self.base_url = "https://news.google.com"

    def _make_request(self, url: str, retries: int = MAX_RETRIES) -> Optional[requests.Response]:
        """
        Make HTTP request with retry logic
        """
        for attempt in range(retries):
            try:
                response = self.session.get(url, timeout=REQUEST_TIMEOUT)
                response.raise_for_status()
                return response
            except requests.RequestException as e:
                logger.warning(f"Google News request failed (attempt {attempt + 1}/{retries}): {e}")
                if attempt < retries - 1:
                    time.sleep(REQUEST_DELAY * (attempt + 1))

        logger.error(f"Failed to fetch {url} after {retries} attempts")
        return None

    def _extract_text_content(self, html_content: str) -> str:
        """Extract clean text content from HTML"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            for script in soup(["script", "style", "nav", "footer", "aside"]):
                script.decompose()
            text = soup.get_text()
            lines = (line.strip() for line in text.splitlines())
            chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
            text = ' '.join(chunk for chunk in chunks if chunk)
            return text[:5000]
        except Exception as e:
            logger.error(f"Failed to extract text content: {e}")
            return ""

    def _parse_google_news_date(self, date_str: str) -> Optional[datetime]:
        """Parse date string from Google News format"""
        try:
            # Google News date formats
            date_formats = [
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%a, %d %b %Y %H:%M:%S %Z",
                "%d %b %Y",
                "%B %d, %Y"
            ]
            
            for fmt in date_formats:
                try:
                    return datetime.strptime(date_str.strip(), fmt)
                except ValueError:
                    continue
            
            # Handle relative dates like "2 hours ago", "1 day ago"
            if 'ago' in date_str.lower():
                return self._parse_relative_date(date_str)
                
        except Exception as e:
            logger.debug(f"Failed to parse date '{date_str}': {e}")
        
        return None

    def _parse_relative_date(self, date_str: str) -> Optional[datetime]:
        """Parse relative date strings like '2 hours ago'"""
        try:
            now = datetime.now()
            date_str = date_str.lower().strip()
            
            if 'minute' in date_str:
                minutes = int(re.search(r'(\d+)', date_str).group(1))
                return now - timedelta(minutes=minutes)
            elif 'hour' in date_str:
                hours = int(re.search(r'(\d+)', date_str).group(1))
                return now - timedelta(hours=hours)
            elif 'day' in date_str:
                days = int(re.search(r'(\d+)', date_str).group(1))
                return now - timedelta(days=days)
            elif 'week' in date_str:
                weeks = int(re.search(r'(\d+)', date_str).group(1))
                return now - timedelta(weeks=weeks)
            elif 'month' in date_str:
                months = int(re.search(r'(\d+)', date_str).group(1))
                return now - timedelta(days=months * 30)
        except:
            pass
        
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
            'cybersecurity', 'cybercrime', 'threat', 'incident'
        ]

        for term in important_terms:
            if term in text_lower:
                keywords.append(term)

        return keywords[:10]

    def _is_india_related(self, text: str) -> bool:
        """Check if text content is related to Indian cybersecurity"""
        text_lower = text.lower()

        indian_indicators = [
            'india', 'indian', 'delhi', 'mumbai', 'bangalore', 'hyderabad',
            'chennai', 'pune', 'aadhaar', 'aadhar', 'digital india',
            'government of india', 'indian government', 'ministry of',
            'indian companies', 'indian banks', 'indian it', 'infosys',
            'tcs', 'wipro', 'tech mahindra', 'hcl', 'state bank of india',
            'icici', 'hdfc', 'paytm', 'phonepe', 'upi', 'indian rupee',
            'cert-in', 'indian computer emergency response team',
            'indian cyber', 'india cyber', 'cyber india'
        ]

        cyber_keywords = [
            'cyber attack', 'data breach', 'ransomware', 'phishing',
            'malware', 'hacking', 'cybersecurity', 'security breach',
            'data leak', 'cyber crime', 'vulnerability', 'exploit'
        ]

        india_score = sum(1 for indicator in indian_indicators if indicator in text_lower)
        cyber_score = sum(1 for keyword in cyber_keywords if keyword in text_lower)
        return india_score > 0 and cyber_score > 0

    def _classify_severity(self, title: str, content: str) -> str:
        """Classify incident severity based on content"""
        text = f"{title} {content}".lower()
        
        critical_indicators = [
            'critical', 'zero-day', 'remote code execution', 'privilege escalation',
            'system compromise', 'data breach', 'ransomware', 'apt',
            'nation-state', 'government', 'infrastructure'
        ]
        
        high_indicators = [
            'high', 'severe', 'vulnerability', 'exploit', 'malware',
            'phishing', 'ddos', 'attack', 'breach'
        ]
        
        medium_indicators = [
            'medium', 'moderate', 'security', 'advisory', 'update',
            'patch', 'fix', 'warning'
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
        
        if 'vulnerability' in text or 'cve' in text:
            return 'Vulnerability'
        elif 'malware' in text or 'ransomware' in text:
            return 'Malware'
        elif 'phishing' in text:
            return 'Phishing'
        elif 'ddos' in text:
            return 'DDoS'
        elif 'apt' in text or 'advanced persistent threat' in text:
            return 'APT'
        elif 'data breach' in text or 'breach' in text:
            return 'Data Breach'
        elif 'hack' in text or 'hacking' in text:
            return 'Hacking'
        else:
            return 'General Security'

    def _classify_affected_sector(self, title: str, content: str) -> str:
        """Classify affected sector"""
        text = f"{title} {content}".lower()
        
        if any(term in text for term in ['bank', 'financial', 'fintech', 'payment']):
            return 'Banking/Financial'
        elif any(term in text for term in ['government', 'ministry', 'department', 'public']):
            return 'Government/Public'
        elif any(term in text for term in ['healthcare', 'hospital', 'medical']):
            return 'Healthcare'
        elif any(term in text for term in ['education', 'university', 'school']):
            return 'Education'
        elif any(term in text for term in ['energy', 'power', 'utility']):
            return 'Energy/Utilities'
        elif any(term in text for term in ['telecom', 'communication']):
            return 'Telecommunications'
        else:
            return 'General'

    def scrape_google_news_search(self, query: str, max_results: int = 50) -> List[Dict[str, Any]]:
        """Scrape Google News search results for a specific query"""
        articles = []
        
        try:
            # Construct Google News search URL
            search_url = f"https://news.google.com/search?q={quote(query)}&hl=en-IN&gl=IN&ceid=IN:en"
            logger.info(f"Scraping Google News for query: {query}")
            
            response = self._make_request(search_url)
            if not response:
                return articles

            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Find article links in Google News results
            article_links = soup.find_all('a', {'data-n-tid': True})
            
            for link in article_links[:max_results]:
                try:
                    # Extract article URL (Google News uses encoded URLs)
                    article_url = link.get('href')
                    if not article_url or article_url.startswith('#'):
                        continue
                    
                    # Make absolute URL
                    if article_url.startswith('/'):
                        article_url = urljoin(self.base_url, article_url)
                    
                    # Extract title
                    title_elem = link.find('h3') or link.find('h4')
                    if not title_elem:
                        continue
                    
                    title = title_elem.get_text(strip=True)
                    if not title or len(title) < 10:
                        continue
                    
                    # Try to extract date from nearby elements
                    date_text = ""
                    parent = link.parent
                    if parent:
                        time_elem = parent.find('time')
                        if time_elem:
                            date_text = time_elem.get('datetime') or time_elem.get_text(strip=True)
                    
                    # Parse date
                    incident_date = self._parse_google_news_date(date_text)
                    
                    # Skip very old articles (older than 30 days)
                    if incident_date and (datetime.now() - incident_date).days > 30:
                        continue
                    
                    # Fetch full content
                    content = self._fetch_article_content(article_url)
                    
                    if content:
                        # Check if India-related
                        full_text = f"{title} {content}"
                        if not self._is_india_related(full_text):
                            continue
                        
                        keywords = self._extract_keywords(full_text)
                        severity = self._classify_severity(title, content)
                        category = self._classify_category(title, content)
                        affected_sector = self._classify_affected_sector(title, content)
                        
                        article = {
                            'title': title,
                            'url': article_url,
                            'description': content,
                            'incident_date': incident_date,
                            'source_id': self._get_google_news_source_id(),
                            'keywords': keywords,
                            'summary': content[:500] if content else title,
                            'india_related': True,
                            'category': category,
                            'severity': severity,
                            'affected_sector': affected_sector,
                            'apt_group': None,
                            'attack_vectors': [],
                            'iocs': []
                        }
                        
                        articles.append(article)
                    
                    time.sleep(REQUEST_DELAY)
                    
                except Exception as e:
                    logger.error(f"Error processing Google News article: {e}")
                    continue

            logger.info(f"Found {len(articles)} India-related articles for query: {query}")
            
        except Exception as e:
            logger.error(f"Failed to scrape Google News for query '{query}': {e}")

        return articles

    def _fetch_article_content(self, url: str) -> Optional[str]:
        """Fetch full article content from URL"""
        try:
            # Check if domain is allowed
            parsed_url = urlparse(url)
            if parsed_url.netloc not in SECURITY_CONFIG.get('allowed_domains', []):
                # For Google News, we'll allow most domains but be cautious
                pass
            
            response = self._make_request(url)
            if not response:
                return None

            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Try to find main content area
            content_selectors = [
                'article', '.article-content', '.post-content',
                '.entry-content', '.content', 'main', '.main-content',
                '.story-body', '.article-body', '.post-body'
            ]
            
            for selector in content_selectors:
                content_elem = soup.select_one(selector)
                if content_elem:
                    return self._extract_text_content(str(content_elem))
            
            # Fallback to body content
            if soup.body:
                return self._extract_text_content(str(soup.body))
            
            return None
            
        except Exception as e:
            logger.debug(f"Failed to fetch article content from {url}: {e}")
            return None

    def _get_google_news_source_id(self) -> int:
        """Get Google News source ID from database"""
        # This should return the actual Google News source ID from database
        # For now, return a placeholder
        return 7  # Placeholder Google News source ID

    def scrape_cybersecurity_news(self, max_results_per_query: int = 20) -> Dict[str, Any]:
        """Scrape cybersecurity news from Google News using multiple queries"""
        results = {
            'total_articles': 0,
            'india_related': 0,
            'queries_processed': 0,
            'errors': []
        }
        
        all_articles = []
        
        try:
            # Define search queries for Indian cybersecurity news
            search_queries = [
                'cybersecurity india',
                'cyber attack india',
                'data breach india',
                'ransomware india',
                'cyber crime india',
                'indian cybersecurity',
                'india cyber security',
                'cyber threat india',
                'digital security india',
                'cyber incident india'
            ]
            
            for query in search_queries:
                try:
                    logger.info(f"Processing query: {query}")
                    articles = self.scrape_google_news_search(query, max_results_per_query)
                    
                    # Deduplicate articles by URL
                    seen_urls = set()
                    unique_articles = []
                    
                    for article in articles:
                        if article['url'] not in seen_urls:
                            seen_urls.add(article['url'])
                            unique_articles.append(article)
                    
                    all_articles.extend(unique_articles)
                    results['queries_processed'] += 1
                    
                    logger.info(f"Query '{query}': {len(unique_articles)} unique articles")
                    
                    # Delay between queries
                    time.sleep(REQUEST_DELAY * 2)
                    
                except Exception as e:
                    error_msg = f"Error processing query '{query}': {str(e)}"
                    results['errors'].append(error_msg)
                    logger.error(error_msg)
            
            # Save articles to database
            saved_count = 0
            for article in all_articles:
                if db_manager.add_incident(article):
                    saved_count += 1
            
            # Log activity
            db_manager.log_scraping_activity(
                source_id=self._get_google_news_source_id(),
                status='success',
                items_found=len(all_articles),
                items_processed=saved_count,
                processing_time=0  # Will be calculated by the calling function
            )
            
            results['total_articles'] = len(all_articles)
            results['india_related'] = len([a for a in all_articles if a.get('india_related')])
            
            logger.info(f"Google News scraping completed: {len(all_articles)} articles, {saved_count} saved")
            
        except Exception as e:
            error_msg = f"Google News scraping error: {str(e)}"
            results['errors'].append(error_msg)
            logger.error(error_msg)
        
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
