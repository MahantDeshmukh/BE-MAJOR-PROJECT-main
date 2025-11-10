"""
Forum scraper for collecting cybersecurity discussions from Reddit and other forums
"""
import requests
import logging
import time
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup
import json
import random

from config import (
    USER_AGENTS, REQUEST_TIMEOUT, REQUEST_DELAY, MAX_RETRIES,
    REDDIT_CONFIG, INDIA_CYBER_KEYWORDS
)
from database.db_setup import db_manager

logger = logging.getLogger(__name__)

class ForumScraperError(Exception):
    """Custom exception for forum scraping errors"""
    pass

class RedditScraper:
    """
    Scraper for Reddit cybersecurity discussions
    """
    
    def __init__(self):
        """Initialize Reddit scraper"""
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'application/json',
        })
    
    def _make_request(self, url: str, retries: int = MAX_RETRIES) -> Optional[Dict]:
        """
        Make request to Reddit API
        
        Args:
            url: URL to request
            retries: Number of retries
            
        Returns:
            JSON response or None if failed
        """
        for attempt in range(retries):
            try:
                response = self.session.get(url, timeout=REQUEST_TIMEOUT)
                response.raise_for_status()
                return response.json()
            except requests.RequestException as e:
                logger.warning(f"Reddit request failed (attempt {attempt + 1}/{retries}): {e}")
                if attempt < retries - 1:
                    time.sleep(REQUEST_DELAY * (attempt + 1))
        
        logger.error(f"Failed to fetch Reddit data from {url} after {retries} attempts")
        return None
    
    def _is_india_cyber_relevant(self, text: str, title: str) -> bool:
        """
        Check if Reddit post is relevant to Indian cybersecurity
        
        Args:
            text: Post content
            title: Post title
            
        Returns:
            True if relevant, False otherwise
        """
        combined_text = f"{title} {text}".lower()
        
        # Indian context indicators
        indian_indicators = [
            'india', 'indian', 'delhi', 'mumbai', 'bangalore', 'hyderabad',
            'chennai', 'pune', 'aadhaar', 'digital india', 'indian government',
            'indian companies', 'indian banks', 'paytm', 'phonepe', 'upi',
            'cert-in', 'indian it', 'infosys', 'tcs', 'wipro'
        ]
        
        # Cybersecurity indicators
        cyber_indicators = [
            'cyber', 'hack', 'breach', 'malware', 'ransomware', 'phishing',
            'vulnerability', 'exploit', 'attack', 'security', 'data leak',
            'ddos', 'apt', 'trojan', 'virus', 'spyware'
        ]
        
        # Check for both Indian and cyber context
        has_indian_context = any(indicator in combined_text for indicator in indian_indicators)
        has_cyber_context = any(indicator in combined_text for indicator in cyber_indicators)
        
        return has_indian_context and has_cyber_context
    
    def _extract_post_data(self, post_data: Dict) -> Optional[Dict[str, Any]]:
        """
        Extract relevant data from Reddit post
        
        Args:
            post_data: Raw Reddit post data
            
        Returns:
            Processed post data or None if not relevant
        """
        try:
            # Extract post details
            title = post_data.get('title', '')
            selftext = post_data.get('selftext', '')
            url = f"https://reddit.com{post_data.get('permalink', '')}"
            created_utc = post_data.get('created_utc', 0)
            subreddit = post_data.get('subreddit', '')
            author = post_data.get('author', 'unknown')
            score = post_data.get('score', 0)
            num_comments = post_data.get('num_comments', 0)
            
            # Convert timestamp
            incident_date = datetime.utcfromtimestamp(created_utc) if created_utc else None
            
            # Skip old posts (older than 7 days)
            if incident_date and (datetime.utcnow() - incident_date).days > 7:
                return None
            
            # Check relevance
            if not self._is_india_cyber_relevant(selftext, title):
                return None
            
            # Extract keywords
            keywords = self._extract_keywords(f"{title} {selftext}")
            
            # Create incident data
            incident_data = {
                'title': title[:500],  # Limit title length
                'description': selftext[:2000] if selftext else title,  # Limit description
                'url': url,
                'incident_date': incident_date,
                'source_id': self._get_reddit_source_id(),
                'keywords': keywords,
                'summary': f"Reddit post from r/{subreddit} by u/{author}. Score: {score}, Comments: {num_comments}",
                'india_related': True,
                'category': 'Discussion',
                'severity': 'Low',  # Forum posts are generally low severity
                'affected_sector': 'Community Discussion'
            }
            
            return incident_data
            
        except Exception as e:
            logger.error(f"Error extracting Reddit post data: {e}")
            return None
    
    def _extract_keywords(self, text: str) -> List[str]:
        """
        Extract cybersecurity keywords from text
        
        Args:
            text: Text to analyze
            
        Returns:
            List of keywords
        """
        keywords = []
        text_lower = text.lower()
        
        # Cybersecurity terms
        cyber_terms = [
            'ransomware', 'malware', 'phishing', 'ddos', 'apt', 'vulnerability',
            'exploit', 'zero-day', 'backdoor', 'trojan', 'spyware', 'botnet',
            'social engineering', 'man in the middle', 'sql injection',
            'cross-site scripting', 'buffer overflow', 'privilege escalation'
        ]
        
        for term in cyber_terms:
            if term in text_lower:
                keywords.append(term)
        
        return keywords[:8]  # Limit to top 8 keywords
    
    def _get_reddit_source_id(self) -> int:
        """Get Reddit source ID from database"""
        # This should return the actual Reddit source ID from database
        # For now, return a placeholder
        return 5  # Placeholder Reddit source ID
    
    def scrape_subreddit(self, subreddit: str, limit: int = 25, time_filter: str = 'week') -> List[Dict[str, Any]]:
        """
        Scrape posts from a specific subreddit
        
        Args:
            subreddit: Subreddit name
            limit: Maximum number of posts to fetch
            time_filter: Time filter (hour, day, week, month)
            
        Returns:
            List of relevant posts
        """
        posts = []
        
        try:
            # Search for India cybersecurity posts
            search_queries = [
                'india cyber', 'india hack', 'india breach', 'indian cyber',
                'india security', 'india malware', 'india ransomware'
            ]
            
            for query in search_queries[:3]:  # Limit to first 3 queries
                url = f"https://www.reddit.com/r/{subreddit}/search.json"
                params = {
                    'q': query,
                    'restrict_sr': 'on',
                    'sort': 'new',
                    'limit': limit // len(search_queries[:3]),
                    't': time_filter
                }
                
                logger.info(f"Searching r/{subreddit} for: {query}")
                
                # Add parameters to URL
                full_url = f"{url}?{'&'.join([f'{k}={v}' for k, v in params.items()])}"
                
                data = self._make_request(full_url)
                if not data or 'data' not in data:
                    continue
                
                # Process posts
                for post in data['data'].get('children', []):
                    post_data = post.get('data', {})
                    incident = self._extract_post_data(post_data)
                    if incident:
                        posts.append(incident)
                
                time.sleep(REQUEST_DELAY)
            
            logger.info(f"Found {len(posts)} relevant posts from r/{subreddit}")
            
        except Exception as e:
            logger.error(f"Failed to scrape r/{subreddit}: {e}")
        
        return posts
    
    def scrape_hot_posts(self, subreddit: str, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Scrape hot posts from subreddit and filter for India cyber content
        
        Args:
            subreddit: Subreddit name
            limit: Maximum number of posts to check
            
        Returns:
            List of relevant posts
        """
        posts = []
        
        try:
            url = f"https://www.reddit.com/r/{subreddit}/hot.json"
            params = {'limit': limit}
            
            full_url = f"{url}?{'&'.join([f'{k}={v}' for k, v in params.items()])}"
            
            logger.info(f"Scraping hot posts from r/{subreddit}")
            
            data = self._make_request(full_url)
            if not data or 'data' not in data:
                return posts
            
            # Process posts
            for post in data['data'].get('children', []):
                post_data = post.get('data', {})
                incident = self._extract_post_data(post_data)
                if incident:
                    posts.append(incident)
            
            logger.info(f"Found {len(posts)} relevant hot posts from r/{subreddit}")
            
        except Exception as e:
            logger.error(f"Failed to scrape hot posts from r/{subreddit}: {e}")
        
        return posts
    
    def scrape_all_subreddits(self) -> List[Dict[str, Any]]:
        """
        Scrape all configured subreddits
        
        Returns:
            List of all relevant posts
        """
        all_posts = []
        
        for subreddit in REDDIT_CONFIG['subreddits']:
            try:
                # Scrape both search results and hot posts
                search_posts = self.scrape_subreddit(subreddit, limit=20)
                hot_posts = self.scrape_hot_posts(subreddit, limit=30)
                
                # Combine and deduplicate
                subreddit_posts = search_posts + hot_posts
                seen_urls = set()
                unique_posts = []
                
                for post in subreddit_posts:
                    if post['url'] not in seen_urls:
                        seen_urls.add(post['url'])
                        unique_posts.append(post)
                
                all_posts.extend(unique_posts)
                
                logger.info(f"Total posts from r/{subreddit}: {len(unique_posts)}")
                
                # Delay between subreddits
                time.sleep(REQUEST_DELAY * 2)
                
            except Exception as e:
                logger.error(f"Error scraping r/{subreddit}: {e}")
        
        return all_posts

class GenericForumScraper:
    """
    Generic scraper for other cybersecurity forums
    """
    
    def __init__(self):
        """Initialize generic forum scraper"""
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': random.choice(USER_AGENTS),
        })
    
    def scrape_security_forum(self, forum_url: str, forum_name: str) -> List[Dict[str, Any]]:
        """
        Scrape generic security forum (placeholder implementation)
        
        Args:
            forum_url: Forum base URL
            forum_name: Forum name for identification
            
        Returns:
            List of forum posts (empty for now)
        """
        # Placeholder implementation - can be extended for specific forums
        logger.info(f"Generic forum scraping not implemented for {forum_name}")
        return []

class ForumDataScraper:
    """
    Main class that coordinates all forum scraping activities
    """
    
    def __init__(self):
        """Initialize forum data scraper"""
        self.reddit_scraper = RedditScraper()
        self.generic_scraper = GenericForumScraper()
    
    def scrape_all_forums(self) -> Dict[str, Any]:
        """
        Scrape all configured forums
        
        Returns:
            Dictionary with scraping results
        """
        all_posts = []
        results = {
            'total_posts': 0,
            'india_related': 0,
            'reddit_posts': 0,
            'errors': []
        }
        
        try:
            # Scrape Reddit
            if REDDIT_CONFIG['enabled']:
                start_time = time.time()
                reddit_posts = self.reddit_scraper.scrape_all_subreddits()
                
                # Save to database
                saved_count = 0
                for post in reddit_posts:
                    if db_manager.add_incident(post):
                        saved_count += 1
                
                all_posts.extend(reddit_posts)
                results['reddit_posts'] = len(reddit_posts)
                
                # Log activity
                db_manager.log_scraping_activity(
                    source_id=5,  # Reddit source ID
                    status='success',
                    items_found=len(reddit_posts),
                    items_processed=saved_count,
                    processing_time=time.time() - start_time
                )
                
                logger.info(f"Reddit scraping completed: {len(reddit_posts)} posts, {saved_count} saved")
        
        except Exception as e:
            error_msg = f"Reddit scraping error: {str(e)}"
            results['errors'].append(error_msg)
            logger.error(error_msg)
        
        # Update results
        results['total_posts'] = len(all_posts)
        results['india_related'] = len([p for p in all_posts if p.get('india_related')])
        
        return results

def main():
    """Main function for testing the forum scraper"""
    scraper = ForumDataScraper()
    results = scraper.scrape_all_forums()
    
    print("Forum Scraping Results:")
    print(f"Total posts: {results['total_posts']}")
    print(f"India-related: {results['india_related']}")
    print(f"Reddit posts: {results['reddit_posts']}")
    
    if results['errors']:
        print(f"Errors: {len(results['errors'])}")
        for error in results['errors']:
            print(f"  - {error}")

if __name__ == "__main__":
    main()
