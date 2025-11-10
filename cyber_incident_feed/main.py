"""
Main entry point for the Cyber Incident Feed Generator
"""
import argparse
import logging
import sys
import os
from datetime import datetime

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config import LOGGING_CONFIG
from database.db_setup import init_database, db_manager
from data_scraper.news_scraper import NewsDataScraper
from data_scraper.forum_scraper import ForumDataScraper
from data_scraper.cert_scraper import CertInScraper
from data_scraper.google_news_scraper import GoogleNewsScraper
from ml_model.train_model import IndianCyberIncidentClassifier
from ml_model.predict import process_all_unprocessed
from scheduler.fetch_scheduler import start_background_scheduler, stop_background_scheduler

# Setup logging
def setup_logging():
    """Setup logging configuration"""
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    logging.basicConfig(
        level=getattr(logging, LOGGING_CONFIG['level']),
        format=LOGGING_CONFIG['format'],
        handlers=[
            logging.FileHandler(LOGGING_CONFIG['file']),
            logging.StreamHandler(sys.stdout)
        ]
    )

logger = logging.getLogger(__name__)

def initialize_system():
    """Initialize the entire system"""
    logger.info("Initializing Cyber Incident Feed Generator...")
    
    try:
        # Initialize database
        init_database()
        logger.info("✅ Database initialized successfully")
        
        # Check if ML model exists, if not train it
        classifier = IndianCyberIncidentClassifier()
        try:
            classifier.load_model()
            logger.info("✅ ML model loaded successfully")
        except FileNotFoundError:
            logger.info("ML model not found, training new model...")
            metrics = classifier.train_model()
            classifier.save_model()
            logger.info(f"✅ ML model trained successfully (Accuracy: {metrics.get('accuracy', 0):.3f})")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ System initialization failed: {e}")
        return False

def run_scraping():
    """Run data scraping manually"""
    logger.info("Starting manual data scraping...")
    
    try:
        # News scraping
        news_scraper = NewsDataScraper()
        news_results = news_scraper.scrape_all_sources()
        logger.info(f"News scraping: {news_results.get('total_articles', 0)} articles, "
                   f"{news_results.get('india_related', 0)} India-related")
        
        # Forum scraping
        forum_scraper = ForumDataScraper()
        forum_results = forum_scraper.scrape_all_forums()
        logger.info(f"Forum scraping: {forum_results.get('total_posts', 0)} posts, "
                   f"{forum_results.get('india_related', 0)} India-related")
        
        # CERT-IN scraping
        cert_scraper = CertInScraper()
        cert_results = cert_scraper.scrape_all_cert_content()
        logger.info(f"CERT-IN scraping: {cert_results.get('total_items', 0)} items, "
                   f"{cert_results.get('advisories', 0)} advisories, {cert_results.get('alerts', 0)} alerts")
        
        # Google News scraping
        google_news_scraper = GoogleNewsScraper()
        google_results = google_news_scraper.scrape_cybersecurity_news()
        logger.info(f"Google News scraping: {google_results.get('total_articles', 0)} articles, "
                   f"{google_results.get('india_related', 0)} India-related")
        
        # Process incidents
        classification_results = process_all_unprocessed()
        logger.info(f"Classification: {classification_results.get('processed_count', 0)} processed, "
                   f"{classification_results.get('relevant_count', 0)} relevant")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Scraping failed: {e}")
        return False

def run_dashboard():
    """Run the Streamlit dashboard"""
    logger.info("Starting Streamlit dashboard...")
    
    try:
        import subprocess
        
        # Get the dashboard path
        dashboard_path = os.path.join(os.path.dirname(__file__), 'dashboard', 'app.py')
        
        # Run streamlit
        cmd = [sys.executable, '-m', 'streamlit', 'run', dashboard_path, '--server.port=8501']
        subprocess.run(cmd)
        
    except Exception as e:
        logger.error(f"❌ Failed to start dashboard: {e}")
        return False

def run_scheduler():
    """Run the background scheduler"""
    logger.info("Starting background scheduler...")
    
    try:
        start_background_scheduler()
        
        # Keep running
        import time
        while True:
            time.sleep(60)
            
    except KeyboardInterrupt:
        logger.info("Received interrupt signal, stopping scheduler...")
        stop_background_scheduler()
        
    except Exception as e:
        logger.error(f"❌ Scheduler failed: {e}")
        stop_background_scheduler()
        return False

def train_model():
    """Train the ML model"""
    logger.info("Training ML model...")
    
    try:
        classifier = IndianCyberIncidentClassifier()
        metrics = classifier.train_model()
        classifier.save_model()
        
        logger.info("✅ Model training completed successfully")
        logger.info(f"Model metrics: Accuracy={metrics.get('accuracy', 0):.3f}, "
                   f"F1-Score={metrics.get('f1_score', 0):.3f}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Model training failed: {e}")
        return False

def show_status():
    """Show system status"""
    logger.info("System Status Report")
    logger.info("=" * 50)
    
    try:
        # Database status
        stats = db_manager.get_incident_stats(days=7)
        logger.info(f"📊 Database Status:")
        logger.info(f"  - Total incidents (7d): {stats['total_incidents']}")
        logger.info(f"  - India-related: {stats['india_incidents']}")
        logger.info(f"  - Relevance rate: {stats['relevance_rate']:.1%}")
        logger.info(f"  - Categories: {len(stats['categories'])}")
        logger.info(f"  - Sources: {len(stats['sources'])}")
        
        # Model status
        try:
            from ml_model.predict import predictor
            if predictor.model_loaded:
                logger.info(f"🤖 ML Model: ✅ Loaded")
                if predictor.classifier.training_date:
                    logger.info(f"  - Last trained: {predictor.classifier.training_date}")
            else:
                logger.info(f"🤖 ML Model: ❌ Not loaded")
        except Exception:
            logger.info(f"🤖 ML Model: ❌ Error checking status")
        
        # Recent activity
        recent_incidents = db_manager.get_recent_incidents(limit=5, days=1, india_only=True)
        logger.info(f"📰 Recent Activity (24h): {len(recent_incidents)} new India-related incidents")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to get status: {e}")
        return False

def main():
    """Main function"""
    setup_logging()
    
    parser = argparse.ArgumentParser(
        description="Cyber Incident Feed Generator - Real-time monitoring of Indian cyberspace threats",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py init              # Initialize the system
  python main.py scrape            # Run manual scraping
  python main.py dashboard         # Start Streamlit dashboard
  python main.py scheduler         # Start background scheduler
  python main.py train             # Train ML model
  python main.py status            # Show system status
  python main.py all               # Initialize + start scheduler + dashboard
        """
    )
    
    parser.add_argument(
        'command',
        choices=['init', 'scrape', 'dashboard', 'scheduler', 'train', 'status', 'all'],
        help='Command to execute'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=8501,
        help='Port for Streamlit dashboard (default: 8501)'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    
    args = parser.parse_args()
    
    # Adjust logging level if debug
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    # Print banner
    logger.info("🔒 Cyber Incident Feed Generator")
    logger.info("🇮🇳 Real-time monitoring of Indian cyberspace threats")
    logger.info("=" * 60)
    logger.info(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Command: {args.command}")
    logger.info("-" * 60)
    
    success = True
    
    try:
        if args.command == 'init':
            success = initialize_system()
            
        elif args.command == 'scrape':
            if initialize_system():
                success = run_scraping()
            else:
                success = False
                
        elif args.command == 'dashboard':
            if initialize_system():
                success = run_dashboard()
            else:
                success = False
                
        elif args.command == 'scheduler':
            if initialize_system():
                success = run_scheduler()
            else:
                success = False
                
        elif args.command == 'train':
            if initialize_system():
                success = train_model()
            else:
                success = False
                
        elif args.command == 'status':
            success = show_status()
            
        elif args.command == 'all':
            # Initialize system
            if not initialize_system():
                success = False
            else:
                # Start scheduler in background
                import threading
                scheduler_thread = threading.Thread(target=run_scheduler)
                scheduler_thread.daemon = True
                scheduler_thread.start()
                logger.info("✅ Background scheduler started")
                
                # Start dashboard
                logger.info("✅ Starting dashboard...")
                success = run_dashboard()
        
        # Final status
        if success:
            logger.info("✅ Command completed successfully")
            sys.exit(0)
        else:
            logger.error("❌ Command failed")
            sys.exit(1)
            
    except KeyboardInterrupt:
        logger.info("👋 Received interrupt signal, shutting down...")
        sys.exit(0)
        
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()



