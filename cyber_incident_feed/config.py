"""
Configuration settings for the Cyber Incident Feed Generator
"""
import os
from datetime import timedelta

# Database Configuration
DATABASE_URL = "sqlite:///cyber_incidents.db"  # Change to PostgreSQL for production
DATABASE_ECHO = False  # Set to True for SQL debugging

# Scraping Configuration
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
]

REQUEST_TIMEOUT = 30  # seconds
REQUEST_DELAY = 2  # seconds between requests
MAX_RETRIES = 3

# India-specific cyber incident keywords (expanded)
INDIA_CYBER_KEYWORDS = [
    # Basic cybersecurity + India
    "cyber attack india", "data breach india", "ransomware india",
    "phishing india", "malware india", "cybersecurity india",
    "indian cyber", "india hacked", "digital india security",
    "indian government cyber", "indian banks cyber", "indian it sector cyber",
    "cyber crime india", "india cybersecurity", "indian companies hacked",
    "digital payments india breach", "aadhaar breach", "india data leak",
    # Additional keywords for better coverage
    "india cyber threat", "indian cyber security", "cyber security india",
    "india ransomware attack", "india data breach", "indian cyber attack",
    "cyber fraud india", "online fraud india", "india cybercrime",
    "indian cybersecurity news", "india security breach", "indian it security",
    "india cyber incident", "indian cyber threat", "cyber attack on india",
    "india hacking", "indian hackers", "india cyber attack news",
    "cert-in india", "indian cert", "india cyber alert",
    "indian government hacked", "india bank hacked", "indian company hacked",
    "upi fraud india", "digital india hack", "india cyber defense",
    "indian cybersecurity companies", "india cyber law", "indian cyber policy",
    # Sector-specific
    "india banking cyber attack", "indian bank cyber security",
    "india healthcare cyber", "indian government cyber security",
    "india telecom cyber", "indian energy cyber attack",
    # Regional
    "delhi cyber crime", "mumbai cyber attack", "bangalore cybersecurity",
    "hyderabad cyber security", "chennai cyber crime"
]

# News Sources Configuration
NEWS_SOURCES = {
    "google_news": {
        "base_url": "https://news.google.com/rss/search",
        "enabled": True,
        "rate_limit": 60  # requests per hour
    },
    "the_hacker_news": {
        "base_url": "https://thehackernews.com",
        "rss_url": "https://feeds.feedburner.com/TheHackersNews",
        "enabled": True
    },
    "bleeping_computer": {
        "base_url": "https://www.bleepingcomputer.com",
        "rss_url": "https://www.bleepingcomputer.com/feed/",
        "enabled": True
    },
    "security_affairs": {
        "base_url": "https://securityaffairs.co",
        "rss_url": "https://securityaffairs.co/wordpress/feed",
        "enabled": True
    },
    "ciso_economic_times": {
        "base_url": "https://ciso.economictimes.indiatimes.com",
        "rss_url": "https://ciso.economictimes.indiatimes.com/rss",
        "enabled": True
    },
    "cyraacs": {
        "base_url": "https://cyraacs.com",
        "rss_url": "https://cyraacs.com/feed",
        "enabled": True
    },
    "cyberops": {
        "base_url": "https://cyberops.in",
        "rss_url": "https://cyberops.in/blog/feed",
        "enabled": True
    },
    "techcrunch_india": {
        "base_url": "https://techcrunch.com",
        "rss_url": "https://techcrunch.com/tag/india/feed/",
        "enabled": True
    },
    "livemint_cyber": {
        "base_url": "https://www.livemint.com",
        "rss_url": "https://www.livemint.com/rss/technology",
        "enabled": True
    },
    "the_hindu_tech": {
        "base_url": "https://www.thehindu.com",
        "rss_url": "https://www.thehindu.com/news/national/feeder/default.rss",
        "enabled": True
    },
    "indian_express_tech": {
        "base_url": "https://indianexpress.com",
        "rss_url": "https://indianexpress.com/section/technology/feed/",
        "enabled": True
    },
    "times_of_india_tech": {
        "base_url": "https://timesofindia.indiatimes.com",
        "rss_url": "https://timesofindia.indiatimes.com/rssfeeds/5880659.cms",
        "enabled": True
    },
    "business_standard_tech": {
        "base_url": "https://www.business-standard.com",
        "rss_url": "https://www.business-standard.com/rss/technology-106.rss",
        "enabled": True
    }
}

# Reddit Configuration
REDDIT_CONFIG = {
    "subreddits": ["cybersecurity", "netsec", "india", "IndiaSpeaks"],
    "enabled": True,
    "posts_limit": 100
}

# Machine Learning Configuration
ML_CONFIG = {
    "model_path": "ml_model/incident_classifier.pkl",
    "vectorizer_path": "ml_model/tfidf_vectorizer.pkl",
    "min_confidence": 0.5,  # Minimum confidence score for relevance
    "retrain_threshold": 1000,  # Retrain after this many new samples
}

# Classification Labels
INCIDENT_CATEGORIES = [
    "Data Breach", "Ransomware", "Phishing", "Malware", 
    "DDoS Attack", "Insider Threat", "Supply Chain Attack",
    "APT Campaign", "Vulnerability Disclosure", "Other"
]

SEVERITY_LEVELS = ["Low", "Medium", "High", "Critical"]

AFFECTED_SECTORS = [
    "Government", "Banking & Finance", "Healthcare", "Education",
    "IT & Software", "Telecommunications", "Energy", "Transportation",
    "Manufacturing", "Retail", "Other"
]

# APT Groups (known groups targeting India)
KNOWN_APT_GROUPS = [
    "Lazarus Group", "APT1", "APT29", "APT40", "Sidewinder",
    "Operation C-Major", "Patchwork", "Confucius", "Transparent Tribe"
]

# Scheduler Configuration
SCHEDULER_CONFIG = {
    "scraping_interval": timedelta(hours=1),  # Run scraper every hour
    "cleanup_interval": timedelta(days=1),    # Clean old data daily
    "model_retrain_interval": timedelta(days=7),  # Retrain model weekly
    "max_age_days": 30,  # Keep incidents for 30 days
}

# Streamlit Dashboard Configuration
DASHBOARD_CONFIG = {
    "page_title": "🔒 Indian Cyber Incident Feed",
    "page_icon": "🛡️",
    "layout": "wide",
    "initial_sidebar_state": "expanded",
    "refresh_interval": 300,  # Auto-refresh every 5 minutes
}

# Visualization Configuration
VIZ_CONFIG = {
    "max_incidents_display": 100,
    "chart_height": 400,
    "chart_width": 800,
    "wordcloud_max_words": 100,
    "color_palette": ["#FF6B6B", "#4ECDC4", "#45B7D1", "#FFA07A", "#98D8C8"]
}

# Logging Configuration
LOGGING_CONFIG = {
    "level": "INFO",
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "file": "logs/cyber_incidents.log",
    "max_bytes": 10 * 1024 * 1024,  # 10MB
    "backup_count": 5
}

# Security Configuration
SECURITY_CONFIG = {
    "max_url_length": 2048,
    "allowed_domains": [
        "thehackernews.com", "bleepingcomputer.com", "securityaffairs.co",
        "krebsonsecurity.com", "darkreading.com", "cyberscoop.com",
        "techcrunch.com", "zdnet.com", "reuters.com", "news.google.com",
        "ciso.economictimes.indiatimes.com", "cyraacs.com", "cyberops.in",
        "livemint.com", "thehindu.com", "indianexpress.com",
        "timesofindia.indiatimes.com", "business-standard.com",
        "economictimes.indiatimes.com", "mint.com", "ndtv.com",
        "news18.com", "firstpost.com", "moneycontrol.com"
    ],
    "sanitize_html": True,
    "respect_robots_txt": True
}

# Environment Variables (override config if set)
DATABASE_URL = os.getenv("DATABASE_URL", DATABASE_URL)
DEBUG = os.getenv("DEBUG", "False").lower() == "true"
