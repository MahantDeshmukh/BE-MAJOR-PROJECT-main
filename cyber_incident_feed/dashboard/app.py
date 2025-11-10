"""
Main Streamlit dashboard for Cyber Incident Feed Generator
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import logging
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import DASHBOARD_CONFIG, VIZ_CONFIG
from database.db_setup import db_manager, init_database
from components.live_feed import render_live_feed
from components.analytics import render_analytics_dashboard
from components.wordcloud_view import render_wordcloud

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Page configuration
st.set_page_config(
    page_title=DASHBOARD_CONFIG['page_title'],
    page_icon=DASHBOARD_CONFIG['page_icon'],
    layout=DASHBOARD_CONFIG['layout'],
    initial_sidebar_state=DASHBOARD_CONFIG['initial_sidebar_state']
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
    }
    .alert-high {
        background-color: #ffebee;
        border-left: 4px solid #f44336;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 0.25rem;
    }
    .alert-medium {
        background-color: #fff3e0;
        border-left: 4px solid #ff9800;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 0.25rem;
    }
    .alert-low {
        background-color: #f1f8e9;
        border-left: 4px solid #4caf50;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 0.25rem;
    }
    .sidebar-info {
        background-color: #e3f2fd;
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
    }
</style>
""", unsafe_allow_html=True)

def initialize_app():
    """Initialize the application"""
    try:
        # Initialize database if needed
        init_database()
        logger.info("Database initialized successfully")
        return True
    except Exception as e:
        st.error(f"Failed to initialize database: {e}")
        logger.error(f"Database initialization failed: {e}")
        return False

def get_dashboard_stats():
    """Get overall dashboard statistics"""
    try:
        stats = db_manager.get_incident_stats(days=7)  # Last 7 days
        return stats
    except Exception as e:
        logger.error(f"Failed to get dashboard stats: {e}")
        return {
            'total_incidents': 0,
            'india_incidents': 0,
            'categories': {},
            'severities': {},
            'sources': {},
            'relevance_rate': 0.0
        }

def render_sidebar():
    """Render the sidebar with navigation and info"""
    st.sidebar.markdown('<div class="sidebar-info">', unsafe_allow_html=True)
    st.sidebar.markdown("### 🛡️ Cyber Incident Feed")
    st.sidebar.markdown("**Real-time monitoring of cybersecurity incidents affecting Indian cyberspace**")
    st.sidebar.markdown('</div>', unsafe_allow_html=True)
    
    # Navigation
    st.sidebar.markdown("### 📍 Navigation")
    page = st.sidebar.selectbox(
        "Select Page",
        ["🏠 Dashboard Overview", "📰 Live Feed", "📊 Analytics", "☁️ Word Cloud", "🧠 ML Insights"]
    )
    
    # Quick stats
    st.sidebar.markdown("### 📈 Quick Stats")
    stats = get_dashboard_stats()
    
    col1, col2 = st.sidebar.columns(2)
    with col1:
        st.metric("Total Incidents", stats['total_incidents'])
        st.metric("India Related", stats['india_incidents'])
    with col2:
        st.metric("Relevance Rate", f"{stats['relevance_rate']:.1%}")
        st.metric("Sources", len(stats['sources']))
    
    # Auto-refresh option
    st.sidebar.markdown("### 🔄 Auto Refresh")
    auto_refresh = st.sidebar.checkbox("Enable Auto Refresh (5 min)")
    if auto_refresh:
        st.rerun()
    
    # Last updated
    st.sidebar.markdown("### ⏰ Last Updated")
    st.sidebar.text(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    return page

def render_dashboard_overview():
    """Render the main dashboard overview"""
    st.markdown('<h1 class="main-header">🔒 Indian Cyber Incident Feed Dashboard</h1>', unsafe_allow_html=True)
    
    # Get statistics
    stats = get_dashboard_stats()
    
    # Key metrics row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric(
            label="🚨 Total Incidents (7d)",
            value=stats['total_incidents'],
            delta=None
        )
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric(
            label="🇮🇳 India Related",
            value=stats['india_incidents'],
            delta=f"{stats['relevance_rate']:.1%} relevance"
        )
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col3:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        high_severity = stats['severities'].get('High', 0) + stats['severities'].get('Critical', 0)
        st.metric(
            label="⚠️ High/Critical",
            value=high_severity,
            delta=None
        )
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col4:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric(
            label="📊 Categories",
            value=len(stats['categories']),
            delta=None
        )
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Recent alerts section
    st.markdown("## 🚨 Recent High-Priority Alerts")
    
    try:
        recent_incidents = db_manager.get_recent_incidents(limit=10, days=3, india_only=True)
        
        if recent_incidents:
            for incident in recent_incidents[:5]:  # Show top 5
                severity_class = f"alert-{incident.severity.lower() if incident.severity else 'low'}"
                
                st.markdown(f'<div class="{severity_class}">', unsafe_allow_html=True)
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.markdown(f"**{incident.title}**")
                    if incident.summary:
                        st.markdown(f"*{incident.summary[:200]}...*")
                    st.markdown(f"🏷️ {incident.category or 'Unknown'} | 🏢 {incident.affected_sector or 'Unknown'}")
                
                with col2:
                    st.markdown(f"**Severity:** {incident.severity or 'Unknown'}")
                    st.markdown(f"**Date:** {incident.incident_date.strftime('%Y-%m-%d') if incident.incident_date else 'Unknown'}")
                    st.markdown(f"**Score:** {incident.relevance_score:.2f}" if incident.relevance_score else "**Score:** N/A")
                
                st.markdown('</div>', unsafe_allow_html=True)
        else:
            st.info("No recent high-priority incidents found.")
    
    except Exception as e:
        st.error(f"Failed to load recent incidents: {e}")
    
    # Charts section
    st.markdown("## 📈 Quick Analytics")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Incidents by category
        if stats['categories']:
            category_df = pd.DataFrame(
                list(stats['categories'].items()),
                columns=['Category', 'Count']
            )
            fig = px.pie(
                category_df,
                values='Count',
                names='Category',
                title='Incidents by Category (Last 7 days)',
                color_discrete_sequence=VIZ_CONFIG['color_palette']
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No categorized incidents to display")
    
    with col2:
        # Incidents by severity
        if stats['severities']:
            severity_df = pd.DataFrame(
                list(stats['severities'].items()),
                columns=['Severity', 'Count']
            )
            # Define severity colors
            severity_colors = {
                'Critical': '#d32f2f',
                'High': '#f57c00',
                'Medium': '#fbc02d',
                'Low': '#388e3c'
            }
            fig = px.bar(
                severity_df,
                x='Severity',
                y='Count',
                title='Incidents by Severity (Last 7 days)',
                color='Severity',
                color_discrete_map=severity_colors
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No severity data to display")

def render_ml_insights():
    """Render ML model insights page"""
    st.markdown("# 🧠 ML Model Insights")
    
    # Model status
    st.markdown("## 🤖 Model Status")
    
    try:
        from ..ml_model.predict import predictor
        
        if predictor.model_loaded:
            st.success("✅ Classification model is loaded and ready")
            if predictor.classifier.training_date:
                st.info(f"Model last trained: {predictor.classifier.training_date.strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            st.warning("⚠️ Classification model not loaded")
            
            if st.button("Train New Model"):
                with st.spinner("Training new model..."):
                    try:
                        predictor._ensure_model_loaded()
                        st.success("✅ Model trained successfully!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Model training failed: {e}")
    
    except Exception as e:
        st.error(f"Failed to check model status: {e}")
    
    # Model performance metrics
    st.markdown("## 📊 Model Performance")
    
    # Sample predictions
    st.markdown("## 🔍 Sample Predictions")
    
    sample_texts = [
        "Indian government websites hit by major cyber attack",
        "US company reports quarterly earnings",
        "AIIMS Delhi ransomware attack affects patient data",
        "New smartphone launched with advanced features"
    ]
    
    try:
        from ..ml_model.predict import classify_single_incident
        
        for i, text in enumerate(sample_texts):
            with st.expander(f"Sample {i+1}: {text[:50]}..."):
                incident_data = {
                    'title': text,
                    'description': '',
                    'url': 'https://example.com',
                    'source_id': 1
                }
                
                result = classify_single_incident(incident_data)
                
                col1, col2 = st.columns(2)
                with col1:
                    st.write("**Original Text:**", text)
                    st.write("**Relevant:**", "✅ Yes" if result.get('is_relevant') else "❌ No")
                with col2:
                    st.write("**Confidence Score:**", f"{result.get('relevance_score', 0):.3f}")
                    st.write("**Predicted Category:**", result.get('category', 'Unknown'))
                    st.write("**Predicted Severity:**", result.get('severity', 'Unknown'))
    
    except Exception as e:
        st.error(f"Failed to generate sample predictions: {e}")

def main():
    """Main application function"""
    # Initialize app
    if not initialize_app():
        st.stop()
    
    # Render sidebar and get selected page
    page = render_sidebar()
    
    # Render selected page
    if page == "🏠 Dashboard Overview":
        render_dashboard_overview()
    elif page == "📰 Live Feed":
        render_live_feed()
    elif page == "📊 Analytics":
        render_analytics_dashboard()
    elif page == "☁️ Word Cloud":
        render_wordcloud()
    elif page == "🧠 ML Insights":
        render_ml_insights()
    
    # Footer
    st.markdown("---")
    st.markdown(
        "<div style='text-align: center; color: #666; font-size: 0.9em;'>"
        "🔒 Cyber Incident Feed Generator | Built with Streamlit & Python | "
        f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        "</div>",
        unsafe_allow_html=True
    )

if __name__ == "__main__":
    main()
