import requests
import feedparser
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
    INDIA_CYBER_KEYWORDS, NEWS_SOURCES, SECURITY_CONFIG
)
from database.db_setup import db_manager
from database.models import Source

logger = logging.getLogger(__name__)


class NewsScraperError(Exception):
    """Custom exception for news scraping errors"""
    pass


class NewsDataScraper:
    """
    Main class for scraping cybersecurity news from various sources
    """

    def __init__(self):
        """Initialize the news scraper"""
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })

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
                logger.warning(f"Request failed (attempt {attempt + 1}/{retries}): {e}")
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
            'aadhaar', 'aadhar', 'digital india', 'make in india',
            'government of india', 'indian government', 'goi',
            'ministry of', 'cert-in', 'indian computer emergency response team',
            'meity', 'ministry of electronics', 'rbi', 'sebi'
        ]
        
        # Indian companies and organizations
        indian_entities = [
            'infosys', 'tcs', 'tata consultancy', 'wipro', 'tech mahindra',
            'hcl', 'state bank of india', 'sbi', 'icici', 'hdfc', 'axis bank',
            'paytm', 'phonepe', 'google pay india', 'flipkart', 'reliance',
            'jio', 'airtel', 'indian railways', 'air india'
        ]
        
        # Cyber security keywords (broader list)
        cyber_keywords = [
            'cyber attack', 'data breach', 'ransomware', 'phishing',
            'malware', 'hacking', 'cybersecurity', 'security breach',
            'data leak', 'cyber crime', 'cybercrime', 'vulnerability',
            'exploit', 'hack', 'hacked', 'breach', 'leak', 'compromised',
            'cyber threat', 'security incident', 'cyber fraud',
            'online fraud', 'digital fraud', 'cyber security',
            'information security', 'network security', 'data security'
        ]
        
        # Check URL for Indian domains
        indian_domains = [
            '.in', '.co.in', '.gov.in', '.ac.in',
            'timesofindia', 'thehindu', 'indianexpress', 'economictimes',
            'livemint', 'business-standard', 'ciso.economictimes',
            'cyraacs.com', 'cyberops.in'
        ]
        
        url_score = sum(1 for domain in indian_domains if domain in url_lower)
        
        # Count indicators
        india_score = sum(1 for indicator in strong_indian_indicators if indicator in text_lower)
        india_score += sum(1 for entity in indian_entities if entity in text_lower)
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
        if any(domain in url_lower for domain in ['.in', 'indian', 'india', 'economictimes', 'cyraacs', 'cyberops']):
            if cyber_score > 0 or any(keyword in text_lower for keyword in ['security', 'cyber', 'hack', 'breach', 'attack', 'data']):
                return True
        
        return False

    def _extract_keywords(self, text: str) -> List[str]:
        """Extract relevant keywords from text"""
        keywords = []
        text_lower = text.lower()

        important_terms = [
            'ransomware', 'phishing', 'malware', 'ddos', 'apt', 'vulnerability',
            'exploit', 'zero-day', 'backdoor', 'trojan', 'spyware', 'adware',
            'botnet', 'crypto', 'blockchain', 'financial', 'banking', 'healthcare',
            'government', 'critical infrastructure', 'supply chain'
        ]

        for term in important_terms:
            if term in text_lower:
                keywords.append(term)

        return keywords[:10]

    def scrape_google_news(self, query: str, max_results: int = 50) -> List[Dict[str, Any]]:
        """Scrape Google News RSS feed for cybersecurity news"""
        articles = []

        try:
            rss_url = f"https://news.google.com/rss/search?q={query}&hl=en-IN&gl=IN&ceid=IN:en"
            logger.info(f"Scraping Google News for query: {query}")
            feed = feedparser.parse(rss_url)

            for entry in feed.entries[:max_results]:
                try:
                    pub_date = None
                    if hasattr(entry, 'published'):
                        pub_date = datetime.strptime(
                            entry.published, "%a, %d %b %Y %H:%M:%S %Z"
                        )

                    content = entry.summary if hasattr(entry, 'summary') else ""
                    article = {
                        'title': entry.title,
                        'url': entry.link,
                        'description': content,
                        'incident_date': pub_date,
                        'source_id': 1,
                        'keywords': self._extract_keywords(f"{entry.title} {content}"),
                        'summary': content[:500] if content else None,
                    }

                    full_text = f"{entry.title} {content}"
                    if self._is_india_related(full_text):
                        article['india_related'] = True
                        articles.append(article)

                except Exception as e:
                    logger.error(f"Error processing Google News entry: {e}")
                    continue

            logger.info(f"Found {len(articles)} India-related articles from Google News")
        except Exception as e:
            logger.error(f"Failed to scrape Google News: {e}")

        return articles

    def scrape_rss_feed(self, rss_url: str, source_id: int, max_results: int = 50) -> List[Dict[str, Any]]:
        """
        Scrape RSS feed from cybersecurity blogs/news sites
        Improved with better date parsing and India detection
        """
        articles = []

        try:
            logger.info(f"Scraping RSS feed: {rss_url}")
            feed = feedparser.parse(rss_url)
            
            if feed.bozo and feed.bozo_exception:
                logger.warning(f"RSS feed parse warning for {rss_url}: {feed.bozo_exception}")
            
            if not feed.entries:
                logger.warning(f"No entries found in RSS feed: {rss_url}")
                return articles

            for entry in feed.entries[:max_results]:
                try:
                    # Parse publication date with multiple fallbacks
                    pub_date = None
                    if hasattr(entry, 'published_parsed') and entry.published_parsed:
                        try:
                            pub_date = datetime(*entry.published_parsed[:6])
                        except (ValueError, TypeError):
                            pass
                    
                    if not pub_date and hasattr(entry, 'updated_parsed') and entry.updated_parsed:
                        try:
                            pub_date = datetime(*entry.updated_parsed[:6])
                        except (ValueError, TypeError):
                            pass
                    
                    if not pub_date and hasattr(entry, 'published'):
                        try:
                            # Try common date formats
                            pub_date_str = entry.published
                            date_formats = [
                                "%a, %d %b %Y %H:%M:%S %Z",
                                "%a, %d %b %Y %H:%M:%S %z",
                                "%Y-%m-%dT%H:%M:%SZ",
                                "%Y-%m-%d %H:%M:%S"
                            ]
                            for fmt in date_formats:
                                try:
                                    pub_date = datetime.strptime(pub_date_str.strip(), fmt)
                                    break
                                except ValueError:
                                    continue
                        except Exception:
                            pass

                    # Skip very old articles (extend to 60 days for better coverage)
                    if pub_date and (datetime.now() - pub_date).days > 60:
                        continue

                    # Get title
                    title = entry.get('title', '').strip()
                    if not title or len(title) < 10:
                        continue
                    
                    # Get content
                    content = ""
                    if hasattr(entry, 'summary'):
                        content = entry.summary
                    elif hasattr(entry, 'description'):
                        content = entry.description
                    elif hasattr(entry, 'content') and entry.content:
                        if isinstance(entry.content, list):
                            content = entry.content[0].get('value', '')
                        else:
                            content = str(entry.content)
                    
                    # Clean HTML from content
                    if content:
                        import re
                        content = re.sub(r'<[^>]+>', '', content)
                        content = content.strip()
                    
                    # Get URL
                    url = entry.get('link', '')
                    if not url:
                        continue
                    
                    # Try to fetch full content (optional, don't fail if it doesn't work)
                    try:
                        full_content = self._fetch_article_content(url)
                        if full_content and len(full_content) > len(content):
                            content = full_content
                    except Exception as e:
                        logger.debug(f"Could not fetch full content for {url}: {e}")
                        # Continue with summary content

                    # Combine text for analysis
                    full_text = f"{title} {content}"
                    
                    # Check if India-related (pass URL for better detection)
                    if not self._is_india_related(full_text, url):
                        continue

                    # Extract keywords
                    keywords = self._extract_keywords(full_text)
                    
                    # Classify severity and category (simple classification)
                    text_lower = full_text.lower()
                    severity = 'Medium'
                    if any(word in text_lower for word in ['critical', 'severe', 'major', 'massive']):
                        severity = 'High'
                    elif any(word in text_lower for word in ['ransomware', 'data breach', 'hacked', 'compromised']):
                        severity = 'High'
                    elif any(word in text_lower for word in ['vulnerability', 'patch', 'update']):
                        severity = 'Medium'
                    
                    category = 'Other'
                    if 'ransomware' in text_lower:
                        category = 'Ransomware'
                    elif 'data breach' in text_lower or 'breach' in text_lower:
                        category = 'Data Breach'
                    elif 'phishing' in text_lower:
                        category = 'Phishing'
                    elif 'malware' in text_lower:
                        category = 'Malware'
                    elif 'vulnerability' in text_lower or 'cve' in text_lower:
                        category = 'Vulnerability Disclosure'
                    elif 'ddos' in text_lower:
                        category = 'DDoS Attack'
                    elif 'apt' in text_lower:
                        category = 'APT Campaign'

                    article = {
                        'title': title,
                        'url': url,
                        'description': content[:2000] if content else title,  # Limit description
                        'incident_date': pub_date,
                        'source_id': source_id,
                        'keywords': keywords,
                        'summary': content[:500] if content else title,
                        'india_related': True,
                        'category': category,
                        'severity': severity,
                    }

                    articles.append(article)

                except Exception as e:
                    logger.error(f"Error processing RSS entry: {e}")
                    logger.debug(f"Entry title: {entry.get('title', 'Unknown')}")
                    import traceback
                    logger.debug(traceback.format_exc())
                    continue

            logger.info(f"Found {len(articles)} India-related articles from RSS feed: {rss_url}")
        except Exception as e:
            logger.error(f"Failed to scrape RSS feed {rss_url}: {e}")
            import traceback
            logger.debug(traceback.format_exc())

        return articles

    def _fetch_article_content(self, url: str) -> Optional[str]:
        """
        Fetch full article content from URL
        Improved with better domain checking and content extraction
        """
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            # Check if domain is in allowed list (more lenient for Indian domains)
            allowed_domains = SECURITY_CONFIG.get('allowed_domains', [])
            is_allowed = any(allowed_domain in domain for allowed_domain in allowed_domains)
            
            # Also allow Indian domains
            if not is_allowed:
                if any(ind_domain in domain for ind_domain in ['.in', 'indian', 'india', 'economictimes', 'cyraacs', 'cyberops']):
                    is_allowed = True
            
            if not is_allowed:
                logger.debug(f"Domain {domain} not in allowed list, skipping content fetch")
                return None

            response = self._make_request(url)
            if not response:
                return None

            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Expanded content selectors for better extraction
            content_selectors = [
                'article', '.article-content', '.post-content',
                '.entry-content', '.content', 'main', '.main-content',
                '.story-body', '.article-body', '.post-body',
                '.article-text', '.post-text', '.entry-text',
                '[role="article"]', '.article-detail', '.story-detail'
            ]

            for selector in content_selectors:
                content_elem = soup.select_one(selector)
                if content_elem:
                    content = self._extract_text_content(str(content_elem))
                    if content and len(content) > 100:  # Ensure we got meaningful content
                        return content

            # Fallback to body content
            if soup.body:
                content = self._extract_text_content(str(soup.body))
                if content and len(content) > 100:
                    return content

            return None

        except Exception as e:
            logger.debug(f"Failed to fetch article content from {url}: {e}")
            return None

    def scrape_all_sources(self) -> Dict[str, Any]:
        """
        Scrape all configured news sources
        Improved with better error handling and Google News integration
        """
        total_articles = []
        results = {'total_articles': 0, 'india_related': 0, 'sources_processed': 0, 'errors': []}

        # Import Google News scraper for better integration
        try:
            from data_scraper.google_news_scraper import GoogleNewsScraper
            google_scraper = GoogleNewsScraper()
            use_google_scraper = True
        except Exception as e:
            logger.warning(f"Could not import GoogleNewsScraper: {e}. Using fallback method.")
            use_google_scraper = False
            google_scraper = None

        with db_manager.get_session() as session:
            sources = session.query(Source).filter(Source.enabled == True).all()

            for source in sources:
                start_time = time.time()
                articles = []

                try:
                    logger.info(f"Processing source: {source.name} (ID: {source.id})")

                    if source.name == "Google News India Cyber":
                        # Use improved Google News scraper if available
                        if use_google_scraper and google_scraper:
                            logger.info("Using GoogleNewsScraper for Google News")
                            google_results = google_scraper.scrape_cybersecurity_news(
                                max_results_per_query=30,
                                source_id=source.id
                            )
                            # Articles are already saved by GoogleNewsScraper
                            articles = []  # Not needed since already saved
                            results['total_articles'] += google_results.get('total_articles', 0)
                            results['india_related'] += google_results.get('india_related', 0)
                        else:
                            # Fallback to RSS method
                            logger.info("Using RSS fallback for Google News")
                            for keyword in INDIA_CYBER_KEYWORDS[:10]:  # Use more keywords
                                try:
                                    articles.extend(self.scrape_google_news(keyword, max_results=25))
                                    time.sleep(REQUEST_DELAY)
                                except Exception as e:
                                    logger.error(f"Error scraping Google News for keyword '{keyword}': {e}")
                                    continue
                    
                    elif source.rss_url:
                        # Scrape RSS feed
                        try:
                            articles = self.scrape_rss_feed(source.rss_url, source.id, max_results=50)
                        except Exception as e:
                            logger.error(f"Error scraping RSS feed {source.rss_url}: {e}")
                            raise
                    else:
                        logger.warning(f"Source {source.name} has no RSS URL, skipping")
                        continue

                    # Save articles to database
                    saved_count = 0
                    if articles:
                        for article in articles:
                            try:
                                if db_manager.add_incident(article):
                                    saved_count += 1
                            except Exception as e:
                                logger.error(f"Error saving article '{article.get('title', 'Unknown')}': {e}")
                                continue

                    processing_time = time.time() - start_time
                    
                    # Log activity
                    try:
                        db_manager.log_scraping_activity(
                            source_id=source.id,
                            status='success',
                            items_found=len(articles),
                            items_processed=saved_count,
                            processing_time=processing_time
                        )
                    except Exception as e:
                        logger.error(f"Error logging scraping activity: {e}")

                    total_articles.extend(articles)
                    results['sources_processed'] += 1
                    logger.info(f"Processed {source.name}: {len(articles)} articles found, {saved_count} saved")

                except Exception as e:
                    error_msg = f"Error processing {source.name}: {str(e)}"
                    results['errors'].append(error_msg)
                    logger.error(error_msg)
                    import traceback
                    logger.debug(traceback.format_exc())
                    
                    try:
                        db_manager.log_scraping_activity(
                            source_id=source.id,
                            status='error',
                            error_message=str(e),
                            processing_time=time.time() - start_time
                        )
                    except Exception as log_error:
                        logger.error(f"Error logging error status: {log_error}")

                # Delay between sources
                time.sleep(REQUEST_DELAY)

        results['total_articles'] = len(total_articles) if 'total_articles' not in results or results['total_articles'] == 0 else results['total_articles']
        results['india_related'] = len([a for a in total_articles if a.get('india_related')]) if total_articles else results.get('india_related', 0)
        return results


def main():
    """Main function for testing the scraper"""
    scraper = NewsDataScraper()
    results = scraper.scrape_all_sources()

    print(f"Scraping Results:")
    print(f"Total articles: {results['total_articles']}")
    print(f"India-related: {results['india_related']}")
    print(f"Sources processed: {results['sources_processed']}")

    if results['errors']:
        print(f"Errors: {len(results['errors'])}")
        for error in results['errors']:
            print(f" - {error}")


if __name__ == "__main__":
    main()
