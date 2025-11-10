"""
Analytics dashboard component for cyber incident data visualization
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from datetime import datetime, timedelta
import logging

# Import from parent directories
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from database.db_setup import db_manager
from config import VIZ_CONFIG

logger = logging.getLogger(__name__)

def render_analytics_dashboard():
    """Render the analytics dashboard page"""
    st.markdown("# 📊 Cyber Incident Analytics")
    st.markdown("Comprehensive analytics and insights on cybersecurity incidents")
    
    # Time period selector
    col1, col2 = st.columns([1, 3])
    with col1:
        analysis_period = st.selectbox(
            "Analysis Period",
            [7, 14, 30, 60, 90],
            index=2,
            format_func=lambda x: f"Last {x} days"
        )
    
    with col2:
        st.info(f"Analyzing data from {datetime.now() - timedelta(days=analysis_period)} to {datetime.now()}")
    
    try:
        # Get comprehensive statistics
        stats = db_manager.get_incident_stats(days=analysis_period)
        incidents = db_manager.get_recent_incidents(limit=1000, days=analysis_period, india_only=False)
        
        if not incidents:
            st.warning(f"No incidents found for the last {analysis_period} days")
            return
        
        # Overall metrics
        st.markdown("## 📈 Key Metrics")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Total Incidents", 
                stats['total_incidents'],
                delta=None
            )
        
        with col2:
            st.metric(
                "India Related", 
                stats['india_incidents'],
                delta=f"{stats['relevance_rate']:.1%}"
            )
        
        with col3:
            high_severity = stats['severities'].get('High', 0) + stats['severities'].get('Critical', 0)
            st.metric(
                "High/Critical Severity",
                high_severity,
                delta=f"{(high_severity/stats['total_incidents']*100):.1f}%" if stats['total_incidents'] > 0 else "0%"
            )
        
        with col4:
            avg_confidence = sum(i.relevance_score for i in incidents if i.relevance_score) / len([i for i in incidents if i.relevance_score])
            st.metric(
                "Avg Confidence Score",
                f"{avg_confidence:.2f}" if incidents else "0.00"
            )
        
        # Charts section
        st.markdown("## 📊 Detailed Analytics")
        
        # Incident trends over time
        st.markdown("### 📈 Incident Trends")
        
        # Prepare timeline data
        timeline_data = []
        for incident in incidents:
            if incident.incident_date:
                timeline_data.append({
                    'Date': incident.incident_date.date(),
                    'India_Related': incident.india_related,
                    'Severity': incident.severity or 'Unknown',
                    'Category': incident.category or 'Unknown'
                })
        
        if timeline_data:
            timeline_df = pd.DataFrame(timeline_data)
            
            # Daily incident counts
            daily_counts = timeline_df.groupby(['Date', 'India_Related']).size().reset_index(name='Count')
            daily_counts['Type'] = daily_counts['India_Related'].map({True: 'India Related', False: 'Other'})
            
            fig = px.line(
                daily_counts,
                x='Date',
                y='Count', 
                color='Type',
                title=f'Daily Incident Trends (Last {analysis_period} days)',
                color_discrete_map={'India Related': '#1f77b4', 'Other': '#ff7f0e'}
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
            
            # Weekly aggregation for better trends
            timeline_df['Week'] = pd.to_datetime(timeline_df['Date']).dt.to_period('W')
            weekly_counts = timeline_df.groupby(['Week', 'India_Related']).size().reset_index(name='Count')
            weekly_counts['Type'] = weekly_counts['India_Related'].map({True: 'India Related', False: 'Other'})
            weekly_counts['Week_Start'] = weekly_counts['Week'].dt.start_time
            
            fig2 = px.bar(
                weekly_counts,
                x='Week_Start',
                y='Count',
                color='Type',
                title=f'Weekly Incident Distribution (Last {analysis_period} days)',
                color_discrete_map={'India Related': '#1f77b4', 'Other': '#ff7f0e'}
            )
            fig2.update_layout(height=400)
            st.plotly_chart(fig2, use_container_width=True)
        
        # Category and severity analysis
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 🏷️ Incident Categories")
            if stats['categories']:
                category_df = pd.DataFrame(
                    list(stats['categories'].items()),
                    columns=['Category', 'Count']
                )
                category_df = category_df.sort_values('Count', ascending=False)
                
                fig = px.pie(
                    category_df,
                    values='Count',
                    names='Category',
                    title='Distribution by Category',
                    color_discrete_sequence=VIZ_CONFIG['color_palette']
                )
                fig.update_traces(textposition='inside', textinfo='percent+label')
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
                
                # Category table
                st.dataframe(category_df, use_container_width=True)
            else:
                st.info("No category data available")
        
        with col2:
            st.markdown("### ⚠️ Severity Levels")
            if stats['severities']:
                severity_df = pd.DataFrame(
                    list(stats['severities'].items()),
                    columns=['Severity', 'Count']
                )
                
                # Order by severity
                severity_order = ['Critical', 'High', 'Medium', 'Low', 'Unknown']
                severity_df['Order'] = severity_df['Severity'].map({s: i for i, s in enumerate(severity_order)})
                severity_df = severity_df.sort_values('Order').drop('Order', axis=1)
                
                severity_colors = {
                    'Critical': '#d32f2f',
                    'High': '#f57c00',
                    'Medium': '#fbc02d', 
                    'Low': '#388e3c',
                    'Unknown': '#9e9e9e'
                }
                
                fig = px.bar(
                    severity_df,
                    x='Severity',
                    y='Count',
                    title='Distribution by Severity',
                    color='Severity',
                    color_discrete_map=severity_colors
                )
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
                
                # Severity table
                st.dataframe(severity_df, use_container_width=True)
            else:
                st.info("No severity data available")
        
        # Sector analysis for India-related incidents
        st.markdown("### 🏢 Affected Sectors (India-related incidents)")
        
        india_incidents = [i for i in incidents if i.india_related]
        if india_incidents:
            sector_counts = {}
            for incident in india_incidents:
                sector = incident.affected_sector or 'Unknown'
                sector_counts[sector] = sector_counts.get(sector, 0) + 1
            
            if sector_counts:
                sector_df = pd.DataFrame(
                    list(sector_counts.items()),
                    columns=['Sector', 'Count']
                )
                sector_df = sector_df.sort_values('Count', ascending=True)
                
                fig = px.bar(
                    sector_df,
                    x='Count',
                    y='Sector',
                    orientation='h',
                    title='Indian Incidents by Affected Sector',
                    color='Count',
                    color_continuous_scale='Blues'
                )
                fig.update_layout(height=max(300, len(sector_df) * 30))
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No India-related incidents found for sector analysis")
        
        # Source analysis
        st.markdown("### 📰 Data Sources Performance")
        
        if stats['sources']:
            source_df = pd.DataFrame(
                list(stats['sources'].items()),
                columns=['Source', 'Incidents']
            )
            source_df = source_df.sort_values('Incidents', ascending=False)
            
            col1, col2 = st.columns(2)
            
            with col1:
                # Source contribution pie chart
                fig = px.pie(
                    source_df.head(8),  # Top 8 sources
                    values='Incidents',
                    names='Source',
                    title='Incident Sources Distribution',
                    color_discrete_sequence=VIZ_CONFIG['color_palette']
                )
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                # Source performance table
                st.markdown("**Source Performance:**")
                st.dataframe(source_df, use_container_width=True)
        
        # Advanced analytics
        st.markdown("## 🔍 Advanced Analytics")
        
        # Correlation analysis
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 📊 Severity vs Confidence Score")
            
            # Prepare data for scatter plot
            scatter_data = []
            for incident in incidents:
                if incident.relevance_score and incident.severity:
                    scatter_data.append({
                        'Confidence_Score': incident.relevance_score,
                        'Severity': incident.severity,
                        'India_Related': incident.india_related,
                        'Title': incident.title[:50] + '...' if len(incident.title) > 50 else incident.title
                    })
            
            if scatter_data:
                scatter_df = pd.DataFrame(scatter_data)
                
                fig = px.scatter(
                    scatter_df,
                    x='Confidence_Score',
                    y='Severity',
                    color='India_Related',
                    title='Incident Confidence vs Severity',
                    hover_data=['Title'],
                    color_discrete_map={True: '#1f77b4', False: '#ff7f0e'}
                )
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Insufficient data for correlation analysis")
        
        with col2:
            st.markdown("### 📅 Incident Frequency Heatmap")
            
            if timeline_data:
                timeline_df = pd.DataFrame(timeline_data)
                timeline_df['Date'] = pd.to_datetime(timeline_df['Date'])
                timeline_df['DayOfWeek'] = timeline_df['Date'].dt.day_name()
                timeline_df['Hour'] = timeline_df['Date'].dt.hour
                
                # Day of week analysis
                dow_counts = timeline_df['DayOfWeek'].value_counts()
                dow_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
                dow_counts = dow_counts.reindex(dow_order, fill_value=0)
                
                fig = px.bar(
                    x=dow_counts.index,
                    y=dow_counts.values,
                    title='Incidents by Day of Week',
                    labels={'x': 'Day of Week', 'y': 'Count'}
                )
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No timeline data available for heatmap")
        
        # Summary insights
        st.markdown("## 💡 Key Insights")
        
        insights = []
        
        # Trend analysis
        if stats['total_incidents'] > 0:
            insights.append(f"📈 **Total Incidents:** {stats['total_incidents']} incidents recorded in the last {analysis_period} days")
            insights.append(f"🇮🇳 **India Focus:** {stats['relevance_rate']:.1%} of incidents are India-related")
        
        # Top categories
        if stats['categories']:
            top_category = max(stats['categories'].items(), key=lambda x: x[1])
            insights.append(f"🏷️ **Most Common Category:** {top_category[0]} ({top_category[1]} incidents)")
        
        # Severity distribution
        if stats['severities']:
            high_critical = stats['severities'].get('High', 0) + stats['severities'].get('Critical', 0)
            if high_critical > 0:
                insights.append(f"⚠️ **High Risk:** {high_critical} high/critical severity incidents require attention")
        
        # Top source
        if stats['sources']:
            top_source = max(stats['sources'].items(), key=lambda x: x[1])
            insights.append(f"📰 **Primary Source:** {top_source[0]} contributed {top_source[1]} incidents")
        
        for insight in insights:
            st.markdown(insight)
        
        # Data export
        st.markdown("## 📥 Data Export")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📊 Export Analytics Summary"):
                summary_data = {
                    'Analysis Period': f'{analysis_period} days',
                    'Total Incidents': stats['total_incidents'],
                    'India Related': stats['india_incidents'],
                    'Relevance Rate': f"{stats['relevance_rate']:.1%}",
                    'Categories': len(stats['categories']),
                    'Sources': len(stats['sources'])
                }
                
                summary_df = pd.DataFrame(list(summary_data.items()), columns=['Metric', 'Value'])
                csv = summary_df.to_csv(index=False)
                
                st.download_button(
                    label="📥 Download Summary CSV",
                    data=csv,
                    file_name=f"analytics_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
        
        with col2:
            if st.button("📋 Export Detailed Data"):
                # Prepare detailed export data
                export_data = []
                for incident in incidents:
                    export_data.append({
                        'Date': incident.incident_date.strftime('%Y-%m-%d %H:%M') if incident.incident_date else '',
                        'Title': incident.title,
                        'Category': incident.category or '',
                        'Severity': incident.severity or '',
                        'Sector': incident.affected_sector or '',
                        'India_Related': incident.india_related,
                        'Confidence_Score': incident.relevance_score or 0,
                        'Source': incident.source.name if incident.source else '',
                        'URL': incident.url
                    })
                
                export_df = pd.DataFrame(export_data)
                csv = export_df.to_csv(index=False)
                
                st.download_button(
                    label="📥 Download Detailed CSV",
                    data=csv,
                    file_name=f"incidents_detailed_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
    
    except Exception as e:
        st.error(f"Failed to load analytics data: {e}")
        logger.error(f"Analytics dashboard error: {e}")
        
        with st.expander("Error Details"):
            st.exception(e)
