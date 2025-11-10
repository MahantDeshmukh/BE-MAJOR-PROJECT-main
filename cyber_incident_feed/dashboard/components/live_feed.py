"""
Live feed component for displaying real-time cyber incidents
"""
import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
import logging

# Import from parent directories
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from database.db_setup import db_manager

logger = logging.getLogger(__name__)

def render_live_feed():
    """Render the live feed page"""
    st.markdown("# 📰 Live Cyber Incident Feed")
    st.markdown("Real-time feed of cybersecurity incidents affecting Indian cyberspace")
    
    # Controls
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        days_filter = st.selectbox(
            "Time Period",
            [1, 3, 7, 14, 30],
            index=2,
            format_func=lambda x: f"Last {x} days"
        )
    
    with col2:
        severity_filter = st.selectbox(
            "Severity Filter",
            ["All", "Critical", "High", "Medium", "Low"]
        )
    
    with col3:
        category_filter = st.selectbox(
            "Category Filter", 
            ["All", "Ransomware", "Phishing", "Malware", "Data Breach", "DDoS Attack", "Other"]
        )
    
    with col4:
        limit = st.selectbox(
            "Items to Show",
            [25, 50, 100, 200],
            index=1
        )
    
    # Refresh button
    col1, col2 = st.columns([1, 4])
    with col1:
        if st.button("🔄 Refresh Feed"):
            st.rerun()
    
    with col2:
        india_only = st.checkbox("Show only India-related incidents", value=True)
    
    # Load incidents
    try:
        incidents = db_manager.get_recent_incidents(
            limit=limit, 
            days=days_filter, 
            india_only=india_only
        )
        
        if not incidents:
            st.info(f"No incidents found for the selected criteria (last {days_filter} days)")
            return
        
        # Filter by severity and category
        filtered_incidents = []
        for incident in incidents:
            # Severity filter
            if severity_filter != "All" and incident.severity != severity_filter:
                continue
            
            # Category filter
            if category_filter != "All" and incident.category != category_filter:
                continue
            
            filtered_incidents.append(incident)
        
        if not filtered_incidents:
            st.warning("No incidents match the selected filters")
            return
        
        st.success(f"Found {len(filtered_incidents)} incidents matching your criteria")
        
        # Create DataFrame for display
        incident_data = []
        for incident in filtered_incidents:
            incident_data.append({
                'Date': incident.incident_date.strftime('%Y-%m-%d %H:%M') if incident.incident_date else 'Unknown',
                'Title': incident.title,
                'Category': incident.category or 'Unknown',
                'Severity': incident.severity or 'Unknown',
                'Sector': incident.affected_sector or 'Unknown',
                'Confidence': f"{incident.relevance_score:.2f}" if incident.relevance_score else 'N/A',
                'Source': incident.source.name if incident.source else 'Unknown',
                'URL': incident.url
            })
        
        df = pd.DataFrame(incident_data)
        
        # Display incidents
        st.markdown("## 📋 Incident List")
        
        # Option to download data
        csv = df.to_csv(index=False)
        st.download_button(
            label="📥 Download as CSV",
            data=csv,
            file_name=f"cyber_incidents_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
        
        # Display with enhanced formatting
        for i, incident in enumerate(filtered_incidents):
            # Determine severity color
            severity_colors = {
                'Critical': '🔴',
                'High': '🟠', 
                'Medium': '🟡',
                'Low': '🟢',
                'Unknown': '⚪'
            }
            
            severity_icon = severity_colors.get(incident.severity, '⚪')
            
            with st.expander(f"{severity_icon} {incident.title[:80]}..." if len(incident.title) > 80 else f"{severity_icon} {incident.title}"):
                
                # Basic info
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.markdown(f"**📅 Date:** {incident.incident_date.strftime('%Y-%m-%d %H:%M') if incident.incident_date else 'Unknown'}")
                    st.markdown(f"**🏷️ Category:** {incident.category or 'Unknown'}")
                    st.markdown(f"**🏢 Sector:** {incident.affected_sector or 'Unknown'}")
                    if incident.apt_group:
                        st.markdown(f"**👥 APT Group:** {incident.apt_group}")
                
                with col2:
                    st.markdown(f"**⚠️ Severity:** {incident.severity or 'Unknown'}")
                    st.markdown(f"**🎯 Confidence:** {incident.relevance_score:.2f}" if incident.relevance_score else "**🎯 Confidence:** N/A")
                    st.markdown(f"**📊 Source:** {incident.source.name if incident.source else 'Unknown'}")
                
                # Description
                if incident.description:
                    st.markdown("**📝 Description:**")
                    st.markdown(incident.description[:500] + ("..." if len(incident.description) > 500 else ""))
                
                # Additional details
                if incident.keywords:
                    st.markdown("**🔍 Keywords:**")
                    keywords_str = ", ".join(incident.keywords[:10]) if isinstance(incident.keywords, list) else str(incident.keywords)
                    st.markdown(f"`{keywords_str}`")
                
                # Indian entities
                if incident.indian_entities:
                    entities = incident.indian_entities
                    if isinstance(entities, dict):
                        entity_parts = []
                        for key, values in entities.items():
                            if values and isinstance(values, list):
                                entity_parts.append(f"**{key.title()}:** {', '.join(values[:3])}")
                        if entity_parts:
                            st.markdown("**🇮🇳 Indian Entities:**")
                            st.markdown(" | ".join(entity_parts))
                
                # Attack vectors
                if incident.attack_vectors:
                    vectors = incident.attack_vectors
                    if isinstance(vectors, list) and vectors:
                        st.markdown(f"**🎯 Attack Vectors:** {', '.join(vectors[:5])}")
                
                # IOCs
                if incident.iocs:
                    iocs = incident.iocs
                    if isinstance(iocs, list) and iocs:
                        st.markdown("**🔍 IOCs:**")
                        for ioc in iocs[:3]:  # Show first 3 IOCs
                            st.code(ioc, language=None)
                
                # Source link
                col1, col2 = st.columns([3, 1])
                with col1:
                    if incident.url:
                        st.markdown(f"**🔗 Source:** [View Original Article]({incident.url})")
                
                with col2:
                    # Admin actions (placeholder)
                    if st.button(f"📝 Edit", key=f"edit_{incident.id}"):
                        st.info("Edit functionality coming soon...")
        
        # Summary statistics
        st.markdown("## 📊 Feed Statistics")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            # Severity distribution
            severity_counts = {}
            for incident in filtered_incidents:
                severity = incident.severity or 'Unknown'
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            if severity_counts:
                st.markdown("**Severity Distribution:**")
                for severity, count in sorted(severity_counts.items()):
                    percentage = (count / len(filtered_incidents)) * 100
                    st.write(f"{severity}: {count} ({percentage:.1f}%)")
        
        with col2:
            # Category distribution
            category_counts = {}
            for incident in filtered_incidents:
                category = incident.category or 'Unknown'
                category_counts[category] = category_counts.get(category, 0) + 1
            
            if category_counts:
                st.markdown("**Category Distribution:**")
                for category, count in sorted(category_counts.items()):
                    percentage = (count / len(filtered_incidents)) * 100
                    st.write(f"{category}: {count} ({percentage:.1f}%)")
        
        with col3:
            # Sector distribution
            sector_counts = {}
            for incident in filtered_incidents:
                sector = incident.affected_sector or 'Unknown'
                sector_counts[sector] = sector_counts.get(sector, 0) + 1
            
            if sector_counts:
                st.markdown("**Sector Distribution:**")
                for sector, count in sorted(sector_counts.items()):
                    percentage = (count / len(filtered_incidents)) * 100
                    st.write(f"{sector}: {count} ({percentage:.1f}%)")
        
        # Timeline chart
        if len(filtered_incidents) > 1:
            st.markdown("## 📈 Incident Timeline")
            
            # Prepare data for timeline
            timeline_data = []
            for incident in filtered_incidents:
                if incident.incident_date:
                    timeline_data.append({
                        'Date': incident.incident_date.date(),
                        'Count': 1,
                        'Severity': incident.severity or 'Unknown'
                    })
            
            if timeline_data:
                timeline_df = pd.DataFrame(timeline_data)
                daily_counts = timeline_df.groupby(['Date', 'Severity']).size().reset_index(name='Count')
                
                fig = px.line(
                    daily_counts,
                    x='Date',
                    y='Count',
                    color='Severity',
                    title='Incident Timeline by Severity',
                    color_discrete_map={
                        'Critical': '#d32f2f',
                        'High': '#f57c00', 
                        'Medium': '#fbc02d',
                        'Low': '#388e3c',
                        'Unknown': '#9e9e9e'
                    }
                )
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
    
    except Exception as e:
        st.error(f"Failed to load incidents: {e}")
        logger.error(f"Live feed error: {e}")
        
        # Show error details in expander for debugging
        with st.expander("Error Details"):
            st.exception(e)
