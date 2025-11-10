"""
Automated scheduler for cyber incident data collection and processing
"""
import logging
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, Any
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.events import EVENT_JOB_EXECUTED, EVENT_JOB_ERROR
import atexit

# Import modules
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import SCHEDULER_CONFIG, ML_CONFIG
from database.db_setup import db_manager, init_database
from data_scraper.news_scraper import NewsDataScraper
from data_scraper.forum_scraper import ForumDataScraper
from ml_model.predict import predictor, process_all_unprocessed
from ml_model.train_model import IndianCyberIncidentClassifier

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CyberIncidentScheduler:
    """
    Main scheduler class for automated cyber incident collection and processing
    """
    
    def __init__(self):
        """Initialize the scheduler"""
        self.scheduler = BackgroundScheduler()
        self.news_scraper = NewsDataScraper()
        self.forum_scraper = ForumDataScraper()
        self.running = False
        self.last_scrape_time = None
        self.last_classification_time = None
        self.stats = {
            'total_scraping_jobs': 0,
            'successful_scrapes': 0,
            'failed_scrapes': 0,
            'total_incidents_processed': 0,
            'total_incidents_classified': 0
        }
        
        # Add event listeners
        self.scheduler.add_listener(self._job_executed, EVENT_JOB_EXECUTED)
        self.scheduler.add_listener(self._job_error, EVENT_JOB_ERROR)
        
        # Register cleanup on exit
        atexit.register(self.stop_scheduler)
    
    def _job_executed(self, event):
        """Handler for successful job execution"""
        logger.info(f"Job '{event.job_id}' executed successfully")
    
    def _job_error(self, event):
        """Handler for job execution errors"""
        logger.error(f"Job '{event.job_id}' failed: {event.exception}")
        self.stats['failed_scrapes'] += 1
    
    def scrape_news_sources(self) -> Dict[str, Any]:
        """
        Scrape news sources for new cyber incidents
        
        Returns:
            Dictionary with scraping results
        """
        logger.info("Starting news scraping job...")
        start_time = time.time()
        
        try:
            results = self.news_scraper.scrape_all_sources()
            
            self.stats['total_scraping_jobs'] += 1
            self.stats['successful_scrapes'] += 1
            self.stats['total_incidents_processed'] += results.get('total_articles', 0)
            
            processing_time = time.time() - start_time
            self.last_scrape_time = datetime.now()
            
            logger.info(f"News scraping completed in {processing_time:.2f}s: "
                       f"{results.get('total_articles', 0)} articles, "
                       f"{results.get('india_related', 0)} India-related")
            
            return results
            
        except Exception as e:
            logger.error(f"News scraping failed: {e}")
            self.stats['failed_scrapes'] += 1
            raise
    
    def scrape_forums(self) -> Dict[str, Any]:
        """
        Scrape forums for new cyber incidents
        
        Returns:
            Dictionary with scraping results
        """
        logger.info("Starting forum scraping job...")
        start_time = time.time()
        
        try:
            results = self.forum_scraper.scrape_all_forums()
            
            self.stats['total_incidents_processed'] += results.get('total_posts', 0)
            
            processing_time = time.time() - start_time
            
            logger.info(f"Forum scraping completed in {processing_time:.2f}s: "
                       f"{results.get('total_posts', 0)} posts, "
                       f"{results.get('india_related', 0)} India-related")
            
            return results
            
        except Exception as e:
            logger.error(f"Forum scraping failed: {e}")
            raise
    
    def classify_incidents(self) -> Dict[str, Any]:
        """
        Classify unprocessed incidents using ML model
        
        Returns:
            Dictionary with classification results
        """
        logger.info("Starting incident classification job...")
        start_time = time.time()
        
        try:
            results = process_all_unprocessed()
            
            self.stats['total_incidents_classified'] += results.get('processed_count', 0)
            self.last_classification_time = datetime.now()
            
            processing_time = time.time() - start_time
            
            logger.info(f"Classification completed in {processing_time:.2f}s: "
                       f"{results.get('processed_count', 0)} processed, "
                       f"{results.get('relevant_count', 0)} relevant")
            
            return results
            
        except Exception as e:
            logger.error(f"Incident classification failed: {e}")
            raise
    
    def cleanup_old_data(self):
        """Clean up old data from database"""
        logger.info("Starting database cleanup job...")
        
        try:
            max_age_days = SCHEDULER_CONFIG['max_age_days']
            db_manager.cleanup_old_data(days=max_age_days)
            logger.info(f"Database cleanup completed: removed data older than {max_age_days} days")
            
        except Exception as e:
            logger.error(f"Database cleanup failed: {e}")
            raise
    
    def retrain_model(self):
        """Retrain the ML model with new data"""
        logger.info("Starting model retraining job...")
        
        try:
            # Check if retraining is needed
            unprocessed_count = len(db_manager.get_unprocessed_incidents(limit=ML_CONFIG['retrain_threshold']))
            
            if unprocessed_count >= ML_CONFIG['retrain_threshold']:
                classifier = IndianCyberIncidentClassifier()
                metrics = classifier.train_model()
                classifier.save_model()
                
                logger.info(f"Model retrained successfully with accuracy: {metrics.get('accuracy', 0):.3f}")
                
                # Reload model in predictor
                predictor._load_model()
                
            else:
                logger.info(f"Model retraining not needed: {unprocessed_count} unprocessed incidents "
                           f"(threshold: {ML_CONFIG['retrain_threshold']})")
                
        except Exception as e:
            logger.error(f"Model retraining failed: {e}")
            raise
    
    def health_check(self):
        """Perform system health check"""
        logger.info("Performing system health check...")
        
        try:
            # Check database connectivity
            with db_manager.get_session() as session:
                from database.models import Source
                source_count = session.query(Source).count()
                logger.info(f"Database health: OK ({source_count} sources configured)")
            
            # Check model status
            if predictor.model_loaded:
                logger.info("ML model health: OK")
            else:
                logger.warning("ML model health: Model not loaded")
            
            # Log current statistics
            logger.info(f"System stats - Scraping jobs: {self.stats['total_scraping_jobs']}, "
                       f"Successful: {self.stats['successful_scrapes']}, "
                       f"Failed: {self.stats['failed_scrapes']}, "
                       f"Incidents processed: {self.stats['total_incidents_processed']}, "
                       f"Classified: {self.stats['total_incidents_classified']}")
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            raise
    
    def start_scheduler(self):
        """Start the scheduler with all jobs"""
        if self.running:
            logger.warning("Scheduler is already running")
            return
        
        logger.info("Starting Cyber Incident Scheduler...")
        
        try:
            # Initialize database
            init_database()
            
            # Add scraping jobs
            self.scheduler.add_job(
                self.scrape_news_sources,
                trigger=IntervalTrigger(hours=1),
                id='news_scraping',
                name='News Sources Scraping',
                replace_existing=True,
                max_instances=1
            )
            
            self.scheduler.add_job(
                self.scrape_forums,
                trigger=IntervalTrigger(hours=2),
                id='forum_scraping',
                name='Forum Scraping',
                replace_existing=True,
                max_instances=1
            )
            
            # Add classification job (runs 15 minutes after scraping)
            self.scheduler.add_job(
                self.classify_incidents,
                trigger=IntervalTrigger(hours=1, start_date=datetime.now() + timedelta(minutes=15)),
                id='incident_classification',
                name='Incident Classification',
                replace_existing=True,
                max_instances=1
            )
            
            # Add cleanup job (daily at 2 AM)
            self.scheduler.add_job(
                self.cleanup_old_data,
                trigger=CronTrigger(hour=2, minute=0),
                id='database_cleanup',
                name='Database Cleanup',
                replace_existing=True
            )
            
            # Add model retraining job (weekly on Sunday at 3 AM)
            self.scheduler.add_job(
                self.retrain_model,
                trigger=CronTrigger(day_of_week='sun', hour=3, minute=0),
                id='model_retraining',
                name='Model Retraining',
                replace_existing=True
            )
            
            # Add health check job (every 6 hours)
            self.scheduler.add_job(
                self.health_check,
                trigger=IntervalTrigger(hours=6),
                id='health_check',
                name='System Health Check',
                replace_existing=True
            )
            
            # Start the scheduler
            self.scheduler.start()
            self.running = True
            
            logger.info("Scheduler started successfully with all jobs configured")
            
            # Log job schedule
            jobs = self.scheduler.get_jobs()
            logger.info(f"Scheduled jobs ({len(jobs)}):")
            for job in jobs:
                logger.info(f"  - {job.name} (ID: {job.id}): {job.trigger}")
            
            # Run initial health check
            self.health_check()
            
        except Exception as e:
            logger.error(f"Failed to start scheduler: {e}")
            raise
    
    def stop_scheduler(self):
        """Stop the scheduler"""
        if not self.running:
            return
        
        logger.info("Stopping Cyber Incident Scheduler...")
        
        try:
            self.scheduler.shutdown(wait=True)
            self.running = False
            logger.info("Scheduler stopped successfully")
            
        except Exception as e:
            logger.error(f"Failed to stop scheduler: {e}")
    
    def get_job_status(self) -> Dict[str, Any]:
        """
        Get current job status and statistics
        
        Returns:
            Dictionary with job status information
        """
        if not self.running:
            return {"status": "stopped", "jobs": []}
        
        jobs_info = []
        for job in self.scheduler.get_jobs():
            jobs_info.append({
                "id": job.id,
                "name": job.name,
                "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
                "trigger": str(job.trigger)
            })
        
        return {
            "status": "running",
            "jobs": jobs_info,
            "stats": self.stats.copy(),
            "last_scrape": self.last_scrape_time.isoformat() if self.last_scrape_time else None,
            "last_classification": self.last_classification_time.isoformat() if self.last_classification_time else None
        }
    
    def run_job_now(self, job_id: str) -> bool:
        """
        Run a specific job immediately
        
        Args:
            job_id: ID of the job to run
            
        Returns:
            True if job was executed, False otherwise
        """
        try:
            job = self.scheduler.get_job(job_id)
            if job:
                job.modify(next_run_time=datetime.now())
                logger.info(f"Job '{job_id}' scheduled to run immediately")
                return True
            else:
                logger.error(f"Job '{job_id}' not found")
                return False
                
        except Exception as e:
            logger.error(f"Failed to run job '{job_id}': {e}")
            return False

# Global scheduler instance
cyber_scheduler = CyberIncidentScheduler()

def start_background_scheduler():
    """Start the background scheduler (convenience function)"""
    cyber_scheduler.start_scheduler()

def stop_background_scheduler():
    """Stop the background scheduler (convenience function)"""
    cyber_scheduler.stop_scheduler()

def get_scheduler_status():
    """Get scheduler status (convenience function)"""
    return cyber_scheduler.get_job_status()

def run_job(job_id: str):
    """Run a job immediately (convenience function)"""
    return cyber_scheduler.run_job_now(job_id)

def main():
    """Main function for running the scheduler"""
    logger.info("Starting Cyber Incident Feed Scheduler...")
    
    try:
        # Start scheduler
        start_background_scheduler()
        
        # Keep the main thread alive
        logger.info("Scheduler is running. Press Ctrl+C to stop.")
        
        while True:
            time.sleep(60)  # Check every minute
            
            # Print status every 10 minutes
            if datetime.now().minute % 10 == 0:
                status = get_scheduler_status()
                logger.info(f"Scheduler status: {status['status']}, "
                           f"Active jobs: {len(status['jobs'])}")
    
    except KeyboardInterrupt:
        logger.info("Received interrupt signal, stopping scheduler...")
        stop_background_scheduler()
        
    except Exception as e:
        logger.error(f"Scheduler error: {e}")
        stop_background_scheduler()
        raise

if __name__ == "__main__":
    main()



