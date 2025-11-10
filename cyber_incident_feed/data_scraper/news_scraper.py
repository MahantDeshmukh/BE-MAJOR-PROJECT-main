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
            'cert-in', 'indian computer emergency response team'
        ]

        cyber_keywords = [
            'cyber attack', 'data breach', 'ransomware', 'phishing',
            'malware', 'hacking', 'cybersecurity', 'security breach',
            'data leak', 'cyber crime', 'vulnerability', 'exploit'
        ]

        india_score = sum(1 for indicator in indian_indicators if indicator in text_lower)
        cyber_score = sum(1 for keyword in cyber_keywords if keyword in text_lower)
        return india_score > 0 and cyber_score > 0

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

    def scrape_rss_feed(self, rss_url: str, source_id: int, max_results: int = 30) -> List[Dict[str, Any]]:
        """Scrape RSS feed from cybersecurity blogs/news sites"""
        articles = []

        try:
            logger.info(f"Scraping RSS feed: {rss_url}")
            feed = feedparser.parse(rss_url)

            for entry in feed.entries[:max_results]:
                try:
                    pub_date = None
                    if hasattr(entry, 'published_parsed') and entry.published_parsed:
                        pub_date = datetime(*entry.published_parsed[:6])
                    elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
                        pub_date = datetime(*entry.updated_parsed[:6])

                    if pub_date and (datetime.now() - pub_date).days > 30:
                        continue

                    content = entry.summary if hasattr(entry, 'summary') else entry.description if hasattr(entry, 'description') else ""
                    full_content = self._fetch_article_content(entry.link)
                    if full_content:
                        content = full_content

                    article = {
                        'title': entry.title,
                        'url': entry.link,
                        'description': content,
                        'incident_date': pub_date,
                        'source_id': source_id,
                        'keywords': self._extract_keywords(f"{entry.title} {content}"),
                        'summary': content[:500] if content else None,
                    }

                    full_text = f"{entry.title} {content}"
                    if self._is_india_related(full_text):
                        article['india_related'] = True
                        articles.append(article)

                except Exception as e:
                    logger.error(f"Error processing RSS entry: {e}")
                    continue

            logger.info(f"Found {len(articles)} India-related articles from RSS feed")
        except Exception as e:
            logger.error(f"Failed to scrape RSS feed {rss_url}: {e}")

        return articles

    def _fetch_article_content(self, url: str) -> Optional[str]:
        """Fetch full article content from URL"""
        try:
            parsed_url = urlparse(url)
            if parsed_url.netloc not in SECURITY_CONFIG['allowed_domains']:
                return None

            response = self._make_request(url)
            if not response:
                return None

            soup = BeautifulSoup(response.content, 'html.parser')
            content_selectors = [
                'article', '.article-content', '.post-content',
                '.entry-content', '.content', 'main', '.main-content'
            ]

            for selector in content_selectors:
                content_elem = soup.select_one(selector)
                if content_elem:
                    return self._extract_text_content(str(content_elem))

            return self._extract_text_content(str(soup.body)) if soup.body else None

        except Exception as e:
            logger.debug(f"Failed to fetch article content from {url}: {e}")
            return None

    def scrape_all_sources(self) -> Dict[str, Any]:
        """Scrape all configured news sources"""
        total_articles = []
        results = {'total_articles': 0, 'india_related': 0, 'sources_processed': 0, 'errors': []}

        with db_manager.get_session() as session:
            sources = session.query(Source).filter(Source.enabled == True).all()

            for source in sources:
                start_time = time.time()
                articles = []

                try:
                    logger.info(f"Processing source: {source.name}")

                    if source.name == "Google News India Cyber":
                        for keyword in INDIA_CYBER_KEYWORDS[:5]:
                            articles.extend(self.scrape_google_news(keyword, max_results=20))
                            time.sleep(REQUEST_DELAY)
                    elif source.rss_url:
                        articles = self.scrape_rss_feed(source.rss_url, source.id)

                    saved_count = 0
                    for article in articles:
                        if db_manager.add_incident(article):
                            saved_count += 1

                    processing_time = time.time() - start_time
                    db_manager.log_scraping_activity(
                        source_id=source.id,
                        status='success',
                        items_found=len(articles),
                        items_processed=saved_count,
                        processing_time=processing_time
                    )

                    total_articles.extend(articles)
                    results['sources_processed'] += 1
                    logger.info(f"Processed {source.name}: {len(articles)} articles, {saved_count} saved")

                except Exception as e:
                    error_msg = f"Error processing {source.name}: {str(e)}"
                    results['errors'].append(error_msg)
                    logger.error(error_msg)
                    db_manager.log_scraping_activity(
                        source_id=source.id,
                        status='error',
                        error_message=str(e),
                        processing_time=time.time() - start_time
                    )

                time.sleep(REQUEST_DELAY)

        results['total_articles'] = len(total_articles)
        results['india_related'] = len([a for a in total_articles if a.get('india_related')])
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
