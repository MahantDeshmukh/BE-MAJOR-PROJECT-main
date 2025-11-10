"""
SQLAlchemy models for the Cyber Incident Feed Generator
"""
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Float, Boolean, 
    ForeignKey, JSON, Index
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class Source(Base):
    """
    Model for data sources (news sites, forums, etc.)
    """
    __tablename__ = "sources"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False, unique=True)
    url = Column(String(500), nullable=False)
    source_type = Column(String(50), nullable=False)  # 'news', 'forum', 'blog', 'social'
    rss_url = Column(String(500), nullable=True)
    enabled = Column(Boolean, default=True)
    last_scraped = Column(DateTime, nullable=True)
    success_rate = Column(Float, default=1.0)  # Success rate for scraping
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship
    incidents = relationship("Incident", back_populates="source")
    
    def __repr__(self):
        return f"<Source(name='{self.name}', type='{self.source_type}')>"


class Incident(Base):
    """
    Model for cyber security incidents
    """
    __tablename__ = "incidents"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    url = Column(String(1000), nullable=False)
    source_id = Column(Integer, ForeignKey("sources.id"), nullable=False)
    
    # Temporal information
    incident_date = Column(DateTime, nullable=True)  # When the incident occurred
    scraped_date = Column(DateTime, default=datetime.utcnow)  # When we found it
    
    # Content analysis
    keywords = Column(JSON, nullable=True)  # List of extracted keywords
    summary = Column(Text, nullable=True)  # Auto-generated summary
    
    # Classification fields
    relevance_score = Column(Float, nullable=True)  # ML model confidence (0-1)
    is_relevant = Column(Boolean, default=False)  # Final relevance decision
    category = Column(String(100), nullable=True)  # Type of incident
    severity = Column(String(20), nullable=True)  # Low, Medium, High, Critical
    affected_sector = Column(String(100), nullable=True)  # Banking, Govt, etc.
    
    # India-specific fields
    india_related = Column(Boolean, default=False)
    indian_entities = Column(JSON, nullable=True)  # List of mentioned Indian organizations
    geography = Column(String(100), nullable=True)  # State/region if mentioned
    
    # Threat intelligence
    apt_group = Column(String(100), nullable=True)  # Attributed APT group
    attack_vectors = Column(JSON, nullable=True)  # List of attack methods
    iocs = Column(JSON, nullable=True)  # Indicators of Compromise
    
    # Processing status
    processed = Column(Boolean, default=False)
    validated = Column(Boolean, default=False)  # Human validation if needed
    
    # Metadata
    language = Column(String(10), default='en')
    word_count = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    source = relationship("Source", back_populates="incidents")
    
    # Indexes for faster queries
    __table_args__ = (
        Index('idx_incident_date', 'incident_date'),
        Index('idx_scraped_date', 'scraped_date'),
        Index('idx_relevance_score', 'relevance_score'),
        Index('idx_india_related', 'india_related'),
        Index('idx_category', 'category'),
        Index('idx_severity', 'severity'),
    )
    
    def __repr__(self):
        return f"<Incident(title='{self.title[:50]}...', relevance={self.relevance_score})>"


class ClassificationHistory(Base):
    """
    Model to track ML model classification history for continuous learning
    """
    __tablename__ = "classification_history"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    model_version = Column(String(50), nullable=False)
    prediction = Column(Float, nullable=False)  # Model confidence score
    predicted_class = Column(String(50), nullable=False)  # Predicted category
    actual_class = Column(String(50), nullable=True)  # Human-verified class
    features_used = Column(JSON, nullable=True)  # Feature vector info
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<ClassificationHistory(incident_id={self.incident_id}, prediction={self.prediction})>"


class ScrapingLog(Base):
    """
    Model to log scraping activities and errors
    """
    __tablename__ = "scraping_logs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    source_id = Column(Integer, ForeignKey("sources.id"), nullable=False)
    status = Column(String(20), nullable=False)  # 'success', 'error', 'partial'
    items_found = Column(Integer, default=0)
    items_processed = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    processing_time = Column(Float, nullable=True)  # Time in seconds
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<ScrapingLog(source_id={self.source_id}, status='{self.status}')>"


class UserFeedback(Base):
    """
    Model to store user feedback for improving classification accuracy
    """
    __tablename__ = "user_feedback"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    user_id = Column(String(100), nullable=True)  # Anonymous user identifier
    feedback_type = Column(String(20), nullable=False)  # 'relevant', 'irrelevant', 'category'
    original_value = Column(String(100), nullable=True)
    suggested_value = Column(String(100), nullable=True)
    confidence = Column(Integer, nullable=True)  # User confidence (1-5)
    comments = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<UserFeedback(incident_id={self.incident_id}, type='{self.feedback_type}')>"
