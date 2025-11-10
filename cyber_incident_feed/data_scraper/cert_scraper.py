"""
CERT-IN (Indian Computer Emergency Response Team) scraper
Scrapes cybersecurity advisories and alerts from cert-in.org.in
"""
import requests
import logging
import time
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import random

from config import (
    USER_AGENTS, REQUEST_TIMEOUT, REQUEST_DELAY, MAX_RETRIES,
    SECURITY_CONFIG
)
from database.db_setup import db_manager

logger = logging.getLogger(__name__)


class CertInScraperError(Exception):
    """Custom exception for CERT-IN scraping errors"""
    pass


class CertInScraper:
    """
    Scraper for CERT-IN (Indian Computer Emergency Response Team) website
    """

    def __init__(self):
        """Initialize the CERT-IN scraper"""
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        self.base_url = "https://www.cert-in.org.in"
        self.advisories_url = "https://www.cert-in.org.in/s2cMainServlet?pageid=PUBADV"
        self.alerts_url = "https://www.cert-in.org.in/s2cMainServlet?pageid=PUBALERT"

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
                logger.warning(f"CERT-IN request failed (attempt {attempt + 1}/{retries}): {e}")
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

    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse date string from CERT-IN format"""
        try:
            # Common CERT-IN date formats
            date_formats = [
                "%d-%m-%Y",
                "%d/%m/%Y",
                "%Y-%m-%d",
                "%d %B %Y",
                "%B %d, %Y"
            ]
            
            for fmt in date_formats:
                try:
                    return datetime.strptime(date_str.strip(), fmt)
                except ValueError:
                    continue
            
            # If no format matches, try to extract date from text
            date_match = re.search(r'(\d{1,2})[-\/](\d{1,2})[-\/](\d{4})', date_str)
            if date_match:
                day, month, year = date_match.groups()
                return datetime(int(year), int(month), int(day))
                
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
            'cert-in', 'indian', 'india', 'cyber attack', 'data breach',
            'security advisory', 'security alert', 'incident response'
        ]

        for term in important_terms:
            if term in text_lower:
                keywords.append(term)

        return keywords[:10]

    def _classify_severity(self, title: str, content: str) -> str:
        """Classify incident severity based on content"""
        text = f"{title} {content}".lower()
        
        critical_indicators = [
            'critical', 'zero-day', 'remote code execution', 'privilege escalation',
            'system compromise', 'data breach', 'ransomware', 'apt'
        ]
        
        high_indicators = [
            'high', 'severe', 'vulnerability', 'exploit', 'malware',
            'phishing', 'ddos', 'attack'
        ]
        
        medium_indicators = [
            'medium', 'moderate', 'security', 'advisory', 'update',
            'patch', 'fix'
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
        elif 'advisory' in text:
            return 'Security Advisory'
        elif 'alert' in text:
            return 'Security Alert'
        else:
            return 'General Security'

    def scrape_advisories(self, max_results: int = 50) -> List[Dict[str, Any]]:
        """Scrape security advisories from CERT-IN"""
        advisories = []
        
        try:
            logger.info("Scraping CERT-IN advisories")
            response = self._make_request(self.advisories_url)
            if not response:
                return advisories

            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Find advisory links and details
            advisory_links = soup.find_all('a', href=True)
            
            for link in advisory_links[:max_results]:
                try:
                    href = link.get('href')
                    if not href or 'javascript:' in href:
                        continue
                    
                    # Make absolute URL
                    full_url = urljoin(self.base_url, href)
                    
                    # Extract title
                    title = link.get_text(strip=True)
                    if not title or len(title) < 10:
                        continue
                    
                    # Try to extract date from link text or nearby elements
                    date_text = ""
                    parent = link.parent
                    if parent:
                        date_text = parent.get_text()
                    
                    # Parse date
                    incident_date = self._parse_date(date_text)
                    
                    # Skip very old advisories (older than 1 year)
                    if incident_date and (datetime.now() - incident_date).days > 365:
                        continue
                    
                    # Fetch full content
                    content = self._fetch_advisory_content(full_url)
                    
                    if content:
                        keywords = self._extract_keywords(f"{title} {content}")
                        severity = self._classify_severity(title, content)
                        category = self._classify_category(title, content)
                        
                        advisory = {
                            'title': title,
                            'url': full_url,
                            'description': content,
                            'incident_date': incident_date,
                            'source_id': self._get_cert_source_id(),
                            'keywords': keywords,
                            'summary': content[:500] if content else title,
                            'india_related': True,
                            'category': category,
                            'severity': severity,
                            'affected_sector': 'Government/Public Sector',
                            'apt_group': None,
                            'attack_vectors': [],
                            'iocs': []
                        }
                        
                        advisories.append(advisory)
                    
                    time.sleep(REQUEST_DELAY)
                    
                except Exception as e:
                    logger.error(f"Error processing advisory link: {e}")
                    continue

            logger.info(f"Found {len(advisories)} CERT-IN advisories")
            
        except Exception as e:
            logger.error(f"Failed to scrape CERT-IN advisories: {e}")

        return advisories

    def scrape_alerts(self, max_results: int = 30) -> List[Dict[str, Any]]:
        """Scrape security alerts from CERT-IN"""
        alerts = []
        
        try:
            logger.info("Scraping CERT-IN alerts")
            response = self._make_request(self.alerts_url)
            if not response:
                return alerts

            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Find alert links and details
            alert_links = soup.find_all('a', href=True)
            
            for link in alert_links[:max_results]:
                try:
                    href = link.get('href')
                    if not href or 'javascript:' in href:
                        continue
                    
                    # Make absolute URL
                    full_url = urljoin(self.base_url, href)
                    
                    # Extract title
                    title = link.get_text(strip=True)
                    if not title or len(title) < 10:
                        continue
                    
                    # Try to extract date from link text or nearby elements
                    date_text = ""
                    parent = link.parent
                    if parent:
                        date_text = parent.get_text()
                    
                    # Parse date
                    incident_date = self._parse_date(date_text)
                    
                    # Skip very old alerts (older than 1 year)
                    if incident_date and (datetime.now() - incident_date).days > 365:
                        continue
                    
                    # Fetch full content
                    content = self._fetch_advisory_content(full_url)
                    
                    if content:
                        keywords = self._extract_keywords(f"{title} {content}")
                        severity = self._classify_severity(title, content)
                        category = self._classify_category(title, content)
                        
                        alert = {
                            'title': title,
                            'url': full_url,
                            'description': content,
                            'incident_date': incident_date,
                            'source_id': self._get_cert_source_id(),
                            'keywords': keywords,
                            'summary': content[:500] if content else title,
                            'india_related': True,
                            'category': category,
                            'severity': severity,
                            'affected_sector': 'Government/Public Sector',
                            'apt_group': None,
                            'attack_vectors': [],
                            'iocs': []
                        }
                        
                        alerts.append(alert)
                    
                    time.sleep(REQUEST_DELAY)
                    
                except Exception as e:
                    logger.error(f"Error processing alert link: {e}")
                    continue

            logger.info(f"Found {len(alerts)} CERT-IN alerts")
            
        except Exception as e:
            logger.error(f"Failed to scrape CERT-IN alerts: {e}")

        return alerts

    def _fetch_advisory_content(self, url: str) -> Optional[str]:
        """Fetch full content of an advisory/alert"""
        try:
            response = self._make_request(url)
            if not response:
                return None

            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Try to find main content area
            content_selectors = [
                'div.content', 'div.main-content', 'div.article-content',
                'div.post-content', 'div.entry-content', 'main', 'article'
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
            logger.debug(f"Failed to fetch advisory content from {url}: {e}")
            return None

    def _get_cert_source_id(self) -> int:
        """Get CERT-IN source ID from database"""
        # This should return the actual CERT-IN source ID from database
        # For now, return a placeholder
        return 6  # Placeholder CERT-IN source ID

    def scrape_all_cert_content(self) -> Dict[str, Any]:
        """Scrape all CERT-IN content (advisories and alerts)"""
        results = {
            'total_items': 0,
            'advisories': 0,
            'alerts': 0,
            'errors': []
        }
        
        try:
            # Scrape advisories
            start_time = time.time()
            advisories = self.scrape_advisories()
            
            # Save advisories to database
            saved_advisories = 0
            for advisory in advisories:
                if db_manager.add_incident(advisory):
                    saved_advisories += 1
            
            results['advisories'] = len(advisories)
            logger.info(f"CERT-IN advisories: {len(advisories)} found, {saved_advisories} saved")
            
            # Log activity
            db_manager.log_scraping_activity(
                source_id=self._get_cert_source_id(),
                status='success',
                items_found=len(advisories),
                items_processed=saved_advisories,
                processing_time=time.time() - start_time
            )
            
            # Scrape alerts
            start_time = time.time()
            alerts = self.scrape_alerts()
            
            # Save alerts to database
            saved_alerts = 0
            for alert in alerts:
                if db_manager.add_incident(alert):
                    saved_alerts += 1
            
            results['alerts'] = len(alerts)
            logger.info(f"CERT-IN alerts: {len(alerts)} found, {saved_alerts} saved")
            
            # Log activity
            db_manager.log_scraping_activity(
                source_id=self._get_cert_source_id(),
                status='success',
                items_found=len(alerts),
                items_processed=saved_alerts,
                processing_time=time.time() - start_time
            )
            
            results['total_items'] = len(advisories) + len(alerts)
            
        except Exception as e:
            error_msg = f"CERT-IN scraping error: {str(e)}"
            results['errors'].append(error_msg)
            logger.error(error_msg)
        
        return results


def main():
    """Main function for testing the CERT-IN scraper"""
    scraper = CertInScraper()
    results = scraper.scrape_all_cert_content()
    
    print("CERT-IN Scraping Results:")
    print(f"Total items: {results['total_items']}")
    print(f"Advisories: {results['advisories']}")
    print(f"Alerts: {results['alerts']}")
    
    if results['errors']:
        print(f"Errors: {len(results['errors'])}")
        for error in results['errors']:
            print(f"  - {error}")


if __name__ == "__main__":
    main()
