"""
Database setup and connection management for Cyber Incident Feed
"""
import logging
import os
from datetime import datetime, timedelta
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker, Session, selectinload
from sqlalchemy.exc import SQLAlchemyError
from contextlib import contextmanager
from typing import List, Dict, Any, Optional

from database.models import Base, Source, Incident, ClassificationHistory, ScrapingLog, UserFeedback
from config import DATABASE_URL, DATABASE_ECHO, NEWS_SOURCES

# Setup logging
logger = logging.getLogger(__name__)

class DatabaseManager:
    """
    Database manager class to handle all database operations
    """
    
    def __init__(self, database_url: str = DATABASE_URL):
        """
        Initialize database manager
        
        Args:
            database_url: Database connection URL
        """
        self.database_url = database_url
        self.engine = None
        self.SessionLocal = None
        self._setup_database()
    
    def _setup_database(self):
        """Setup database engine and session"""
        try:
            self.engine = create_engine(
                self.database_url,
                echo=DATABASE_ECHO,
                pool_pre_ping=True,  # Verify connections before use
                pool_recycle=3600   # Recycle connections every hour
            )
            # Set expire_on_commit=False to prevent objects from being expired
            # when session closes, allowing them to be used outside session context
            self.SessionLocal = sessionmaker(bind=self.engine, expire_on_commit=False)
            logger.info(f"Database engine created successfully: {self.database_url}")
        except Exception as e:
            logger.error(f"Failed to setup database: {e}")
            raise
    
    def create_tables(self):
        """Create all database tables"""
        try:
            Base.metadata.create_all(bind=self.engine)
            logger.info("Database tables created successfully")
            self._initialize_default_sources()
        except Exception as e:
            logger.error(f"Failed to create tables: {e}")
            raise
    
    def drop_tables(self):
        """Drop all database tables (use with caution)"""
        try:
            Base.metadata.drop_all(bind=self.engine)
            logger.warning("All database tables dropped")
        except Exception as e:
            logger.error(f"Failed to drop tables: {e}")
            raise
    
    @contextmanager
    def get_session(self) -> Session:
        """
        Get database session with automatic cleanup
        
        Yields:
            Session: SQLAlchemy database session
        """
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            session.close()
    
    def _initialize_default_sources(self):
        """Initialize default news sources from config"""
        with self.get_session() as session:
            # Define all default sources
            default_sources = [
                Source(
                    name="Google News India Cyber",
                    url="https://news.google.com/rss/search?q=cyber+attack+india",
                    source_type="news",
                    rss_url="https://news.google.com/rss/search?q=cyber+attack+india"
                ),
                Source(
                    name="The Hacker News",
                    url="https://thehackernews.com",
                    source_type="blog",
                    rss_url="https://feeds.feedburner.com/TheHackersNews"
                ),
                Source(
                    name="Bleeping Computer",
                    url="https://www.bleepingcomputer.com",
                    source_type="news",
                    rss_url="https://www.bleepingcomputer.com/feed/"
                ),
                Source(
                    name="Security Affairs",
                    url="https://securityaffairs.co",
                    source_type="blog",
                    rss_url="https://securityaffairs.co/wordpress/feed"
                ),
                Source(
                    name="Reddit Cybersecurity",
                    url="https://reddit.com/r/cybersecurity",
                    source_type="forum"
                ),
                Source(
                    name="CISO Economic Times India",
                    url="https://ciso.economictimes.indiatimes.com",
                    source_type="news",
                    rss_url="https://ciso.economictimes.indiatimes.com/rss"
                ),
                Source(
                    name="CyRaACS",
                    url="https://cyraacs.com",
                    source_type="blog",
                    rss_url="https://cyraacs.com/feed"
                ),
                Source(
                    name="Cyberops",
                    url="https://cyberops.in",
                    source_type="blog",
                    rss_url="https://cyberops.in/blog/feed"
                ),
                Source(
                    name="Livemint Technology",
                    url="https://www.livemint.com",
                    source_type="news",
                    rss_url="https://www.livemint.com/rss/technology"
                ),
                Source(
                    name="The Hindu Technology",
                    url="https://www.thehindu.com",
                    source_type="news",
                    rss_url="https://www.thehindu.com/news/national/feeder/default.rss"
                ),
                Source(
                    name="Indian Express Technology",
                    url="https://indianexpress.com",
                    source_type="news",
                    rss_url="https://indianexpress.com/section/technology/feed/"
                ),
                Source(
                    name="Times of India Technology",
                    url="https://timesofindia.indiatimes.com",
                    source_type="news",
                    rss_url="https://timesofindia.indiatimes.com/rssfeeds/5880659.cms"
                ),
                Source(
                    name="Business Standard Technology",
                    url="https://www.business-standard.com",
                    source_type="news",
                    rss_url="https://www.business-standard.com/rss/technology-106.rss"
                ),
            ]
            
            # Check if sources already exist and add missing ones
            existing_sources = session.query(Source).all()
            existing_names = {source.name for source in existing_sources}
            
            if existing_names:
                # Add only missing sources (by name)
                new_sources = [s for s in default_sources if s.name not in existing_names]
                
                if new_sources:
                    for source in new_sources:
                        session.add(source)
                    logger.info(f"Added {len(new_sources)} new sources to existing database")
                else:
                    logger.info(f"Found {len(existing_names)} existing sources, all default sources already present")
            else:
                # First time initialization - add all sources
                for source in default_sources:
                    session.add(source)
                logger.info(f"Initialized {len(default_sources)} default sources")
    
    def get_sources(self, enabled_only: bool = True) -> List[Source]:
        """
        Get all sources from database
        
        Args:
            enabled_only: If True, return only enabled sources
            
        Returns:
            List of Source objects
        """
        with self.get_session() as session:
            query = session.query(Source)
            if enabled_only:
                query = query.filter(Source.enabled == True)
            return query.all()
    
    def add_incident(self, incident_data: Dict[str, Any]) -> Optional[int]:
        """
        Add new incident to database
        
        Args:
            incident_data: Dictionary containing incident information
            
        Returns:
            ID of created incident or None if failed
        """
        try:
            with self.get_session() as session:
                # Check for duplicate URLs
                existing = session.query(Incident).filter(
                    Incident.url == incident_data.get('url')
                ).first()
                
                if existing:
                    logger.debug(f"Incident already exists: {incident_data.get('url')}")
                    return existing.id
                
                incident = Incident(**incident_data)
                session.add(incident)
                session.flush()  # Get the ID
                incident_id = incident.id
                logger.debug(f"Added new incident: {incident_id}")
                return incident_id
                
        except Exception as e:
            logger.error(f"Failed to add incident: {e}")
            return None
    
    def get_recent_incidents(self, 
                           limit: int = 100, 
                           days: int = 7,
                           india_only: bool = True) -> List[Incident]:
        """
        Get recent incidents from database
        
        Args:
            limit: Maximum number of incidents to return
            days: Number of days to look back
            india_only: If True, return only India-related incidents
            
        Returns:
            List of Incident objects
        """
        with self.get_session() as session:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            query = session.query(Incident).options(
                selectinload(Incident.source)
            ).filter(
                Incident.scraped_date >= cutoff_date
            )
            
            if india_only:
                query = query.filter(Incident.india_related == True)
            
            incidents = query.order_by(
                Incident.scraped_date.desc()
            ).limit(limit).all()
            
            # With expire_on_commit=False and selectinload, objects and their
            # relationships remain accessible after session closes
            return incidents
    
    def get_incident_stats(self, days: int = 30) -> Dict[str, Any]:
        """
        Get statistics about incidents
        
        Args:
            days: Number of days to analyze
            
        Returns:
            Dictionary containing statistics
        """
        with self.get_session() as session:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Total incidents
            total_incidents = session.query(Incident).filter(
                Incident.scraped_date >= cutoff_date
            ).count()
            
            # India-related incidents
            india_incidents = session.query(Incident).filter(
                Incident.scraped_date >= cutoff_date,
                Incident.india_related == True
            ).count()
            
            # By category
            category_stats = session.query(
                Incident.category,
                func.count(Incident.id)
            ).filter(
                Incident.scraped_date >= cutoff_date,
                Incident.india_related == True
            ).group_by(Incident.category).all()
            
            # By severity
            severity_stats = session.query(
                Incident.severity,
                func.count(Incident.id)
            ).filter(
                Incident.scraped_date >= cutoff_date,
                Incident.india_related == True
            ).group_by(Incident.severity).all()
            
            # By source
            source_stats = session.query(
                Source.name,
                func.count(Incident.id)
            ).join(Incident).filter(
                Incident.scraped_date >= cutoff_date
            ).group_by(Source.name).all()
            
            return {
                'total_incidents': total_incidents,
                'india_incidents': india_incidents,
                'categories': dict(category_stats),
                'severities': dict(severity_stats),
                'sources': dict(source_stats),
                'relevance_rate': india_incidents / total_incidents if total_incidents > 0 else 0
            }
    
    def log_scraping_activity(self, source_id: int, status: str, 
                            items_found: int = 0, items_processed: int = 0,
                            error_message: str = None, processing_time: float = None):
        """
        Log scraping activity
        
        Args:
            source_id: ID of the source
            status: Status of scraping ('success', 'error', 'partial')
            items_found: Number of items found
            items_processed: Number of items successfully processed
            error_message: Error message if any
            processing_time: Time taken for processing in seconds
        """
        try:
            with self.get_session() as session:
                log_entry = ScrapingLog(
                    source_id=source_id,
                    status=status,
                    items_found=items_found,
                    items_processed=items_processed,
                    error_message=error_message,
                    processing_time=processing_time
                )
                session.add(log_entry)
                
                # Update source last_scraped timestamp
                source = session.query(Source).get(source_id)
                if source:
                    source.last_scraped = datetime.utcnow()
                    
        except Exception as e:
            logger.error(f"Failed to log scraping activity: {e}")
    
    def cleanup_old_data(self, days: int = 30):
        """
        Clean up old data from database
        
        Args:
            days: Remove data older than this many days
        """
        try:
            with self.get_session() as session:
                cutoff_date = datetime.utcnow() - timedelta(days=days)
                
                # Delete old incidents
                deleted_incidents = session.query(Incident).filter(
                    Incident.scraped_date < cutoff_date
                ).delete()
                
                # Delete old scraping logs
                deleted_logs = session.query(ScrapingLog).filter(
                    ScrapingLog.created_at < cutoff_date
                ).delete()
                
                logger.info(f"Cleaned up {deleted_incidents} old incidents and {deleted_logs} old logs")
                
        except Exception as e:
            logger.error(f"Failed to cleanup old data: {e}")
    
    def get_unprocessed_incidents(self, limit: int = 100) -> List[Incident]:
        """
        Get incidents that haven't been processed by ML model yet
        
        Args:
            limit: Maximum number of incidents to return
            
        Returns:
            List of unprocessed Incident objects
        """
        with self.get_session() as session:
            incidents = session.query(Incident).options(
                selectinload(Incident.source)
            ).filter(
                Incident.processed == False
            ).limit(limit).all()
            
            # With expire_on_commit=False and selectinload, objects and their
            # relationships remain accessible after session closes
            return incidents
    
    def update_incident_classification(self, incident_id: int, 
                                     relevance_score: float,
                                     is_relevant: bool,
                                     category: str = None,
                                     severity: str = None):
        """
        Update incident classification results
        
        Args:
            incident_id: ID of the incident
            relevance_score: ML model confidence score
            is_relevant: Whether incident is relevant to India
            category: Incident category
            severity: Incident severity
        """
        try:
            with self.get_session() as session:
                incident = session.query(Incident).get(incident_id)
                if incident:
                    incident.relevance_score = relevance_score
                    incident.is_relevant = is_relevant
                    incident.india_related = is_relevant
                    incident.processed = True
                    
                    if category:
                        incident.category = category
                    if severity:
                        incident.severity = severity
                    
                    incident.updated_at = datetime.utcnow()
                    
        except Exception as e:
            logger.error(f"Failed to update incident classification: {e}")


# Global database manager instance
db_manager = DatabaseManager()

def init_database():
    """Initialize database tables"""
    db_manager.create_tables()

def get_db_session():
    """Get database session (for external use)"""
    return db_manager.get_session()

if __name__ == "__main__":
    # Initialize database when run directly
    init_database()
    print("Database initialized successfully!")
